use super::lexer::{tokenize, SpannedToken, Token};
use crate::errors::FilterError;
use crate::packet::PacketRecord;

#[derive(Debug, Clone, PartialEq)]
pub enum CompOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
    Contains,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Number(u64),
    String(String),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Comparison {
        field: String,
        op: CompOp,
        value: Value,
    },
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Not(Box<Expr>),
}

pub struct Parser {
    tokens: Vec<SpannedToken>,
    pos: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 20;

impl Parser {
    pub fn new(tokens: Vec<SpannedToken>) -> Self {
        Self {
            tokens,
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos).map(|st| &st.token)
    }

    fn peek_spanned(&self) -> Option<&SpannedToken> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Token> {
        if self.pos < self.tokens.len() {
            let tok = self.tokens[self.pos].token.clone();
            self.pos += 1;
            Some(tok)
        } else {
            None
        }
    }

    pub fn parse(&mut self) -> Result<Expr, FilterError> {
        if self.tokens.is_empty() {
            return Err(FilterError::SyntaxError {
                position: 0,
                message: "Empty filter expression".to_string(),
            });
        }
        let expr = self.parse_or()?;
        if self.pos < self.tokens.len() {
            let st = &self.tokens[self.pos];
            return Err(FilterError::SyntaxError {
                position: st.start,
                message: format!("Unexpected token after expression: {:?}", st.token),
            });
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_and()?;
        while let Some(Token::Or) = self.peek() {
            self.next();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, FilterError> {
        let mut left = self.parse_not()?;
        while let Some(Token::And) = self.peek() {
            self.next();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, FilterError> {
        if let Some(Token::Not) = self.peek() {
            self.next();
            let sub = self.parse_not()?;
            Ok(Expr::Not(Box::new(sub)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, FilterError> {
        if self.depth > MAX_DEPTH {
            return Err(FilterError::NestingTooDeep(MAX_DEPTH));
        }

        match self.peek() {
            Some(Token::LParen) => {
                self.next();
                self.depth += 1;
                let expr = self.parse_or()?;
                self.depth -= 1;
                if let Some(Token::RParen) = self.peek() {
                    self.next();
                    Ok(expr)
                } else {
                    let pos = self
                        .tokens
                        .get(self.pos.saturating_sub(1))
                        .map(|t| t.end)
                        .unwrap_or(0);
                    Err(FilterError::SyntaxError {
                        position: pos,
                        message: "Expected closing ')'".to_string(),
                    })
                }
            }
            Some(Token::Ident(_)) => self.parse_comparison(),
            other => {
                let pos = self.tokens.get(self.pos).map(|t| t.start).unwrap_or(0);
                Err(FilterError::SyntaxError {
                    position: pos,
                    message: format!("Expected field identifier or '(', got {:?}", other),
                })
            }
        }
    }

    fn parse_comparison(&mut self) -> Result<Expr, FilterError> {
        let field_st = match self.next() {
            Some(Token::Ident(name)) => name,
            _ => unreachable!(),
        };

        let field_lower = field_st.to_lowercase();
        validate_field(&field_lower)?;

        let op = match self.peek() {
            Some(Token::Eq) => {
                self.next();
                CompOp::Eq
            }
            Some(Token::Ne) => {
                self.next();
                CompOp::Ne
            }
            Some(Token::Gt) => {
                self.next();
                CompOp::Gt
            }
            Some(Token::Lt) => {
                self.next();
                CompOp::Lt
            }
            Some(Token::Gte) => {
                self.next();
                CompOp::Gte
            }
            Some(Token::Lte) => {
                self.next();
                CompOp::Lte
            }
            Some(Token::Contains) => {
                self.next();
                CompOp::Contains
            }
            _ => {
                // If it's a boolean flag like `tcp.flags.syn` without an explicit operator
                if field_lower.starts_with("tcp.flags.") {
                    return Ok(Expr::Comparison {
                        field: field_lower,
                        op: CompOp::Eq,
                        value: Value::Bool(true),
                    });
                } else {
                    let pos = self.peek_spanned().map(|t| t.start).unwrap_or(0);
                    return Err(FilterError::SyntaxError {
                        position: pos,
                        message: format!(
                            "Expected operator (==, !=, >, <, contains) after field '{}'",
                            field_lower
                        ),
                    });
                }
            }
        };

        let value = match self.next() {
            Some(Token::Number(n)) => Value::Number(n),
            Some(Token::StringLit(s)) => {
                let lower = s.to_lowercase();
                if lower == "true" {
                    Value::Bool(true)
                } else if lower == "false" {
                    Value::Bool(false)
                } else {
                    Value::String(s)
                }
            }
            Some(Token::Ident(s)) => {
                let lower = s.to_lowercase();
                if lower == "true" {
                    Value::Bool(true)
                } else if lower == "false" {
                    Value::Bool(false)
                } else {
                    Value::String(s)
                }
            }
            other => {
                let pos = self
                    .tokens
                    .get(self.pos.saturating_sub(1))
                    .map(|t| t.end)
                    .unwrap_or(0);
                return Err(FilterError::SyntaxError {
                    position: pos,
                    message: format!("Expected comparison value, got {:?}", other),
                });
            }
        };

        Ok(Expr::Comparison {
            field: field_lower,
            op,
            value,
        })
    }
}

pub fn validate_field(field: &str) -> Result<(), FilterError> {
    match field {
        "ip.src" | "ip.dst" | "ip.version" | "tcp.srcport" | "tcp.dstport" | "tcp.port"
        | "tcp.flags.syn" | "tcp.flags.ack" | "tcp.flags.rst" | "udp.srcport" | "udp.dstport"
        | "udp.port" | "protocol" | "frame.len" | "host" | "dns.qname" => Ok(()),
        _ => Err(FilterError::UnknownField(field.to_string())),
    }
}

impl Expr {
    pub fn evaluate(&self, pkt: &PacketRecord) -> bool {
        match self {
            Expr::And(left, right) => left.evaluate(pkt) && right.evaluate(pkt),
            Expr::Or(left, right) => left.evaluate(pkt) || right.evaluate(pkt),
            Expr::Not(sub) => !sub.evaluate(pkt),
            Expr::Comparison { field, op, value } => evaluate_comparison(field, op, value, pkt),
        }
    }
}

fn evaluate_comparison(field: &str, op: &CompOp, value: &Value, pkt: &PacketRecord) -> bool {
    match field {
        "ip.src" => {
            let actual = pkt.source_ip.as_deref().unwrap_or("");
            compare_str(actual, op, value)
        }
        "ip.dst" => {
            let actual = pkt.destination_ip.as_deref().unwrap_or("");
            compare_str(actual, op, value)
        }
        "host" => {
            let src = pkt.source_ip.as_deref().unwrap_or("");
            let dst = pkt.destination_ip.as_deref().unwrap_or("");
            compare_str(src, op, value) || compare_str(dst, op, value)
        }
        "ip.version" => {
            let v = if pkt.network_protocol == "IPv6" {
                6
            } else if pkt.network_protocol == "IPv4" {
                4
            } else {
                0
            };
            compare_num(v, op, value)
        }
        "tcp.srcport" => {
            let p = pkt.source_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("TCP") && compare_num(p, op, value)
        }
        "tcp.dstport" => {
            let p = pkt.destination_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("TCP") && compare_num(p, op, value)
        }
        "tcp.port" => {
            let sp = pkt.source_port.unwrap_or(0) as u64;
            let dp = pkt.destination_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("TCP")
                && (compare_num(sp, op, value) || compare_num(dp, op, value))
        }
        "udp.srcport" => {
            let p = pkt.source_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("UDP") && compare_num(p, op, value)
        }
        "udp.dstport" => {
            let p = pkt.destination_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("UDP") && compare_num(p, op, value)
        }
        "udp.port" => {
            let sp = pkt.source_port.unwrap_or(0) as u64;
            let dp = pkt.destination_port.unwrap_or(0) as u64;
            pkt.transport_protocol.as_deref() == Some("UDP")
                && (compare_num(sp, op, value) || compare_num(dp, op, value))
        }
        "protocol" => {
            let p = pkt.protocol_display();
            compare_str(&p, op, value)
        }
        "frame.len" => {
            let len = pkt.captured_length as u64;
            compare_num(len, op, value)
        }
        "tcp.flags.syn" => {
            let syn = pkt.tcp_flags.map(|f| f.syn).unwrap_or(false);
            compare_bool(syn, op, value)
        }
        "tcp.flags.ack" => {
            let ack = pkt.tcp_flags.map(|f| f.ack).unwrap_or(false);
            compare_bool(ack, op, value)
        }
        "tcp.flags.rst" => {
            let rst = pkt.tcp_flags.map(|f| f.rst).unwrap_or(false);
            compare_bool(rst, op, value)
        }
        "dns.qname" => {
            // Check layers for DNS query name
            for layer in &pkt.layers {
                if layer.name.contains("Domain Name System") {
                    for field in &layer.fields {
                        if field.name.starts_with("Query") && compare_str(&field.value, op, value) {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn compare_str(actual: &str, op: &CompOp, expected: &Value) -> bool {
    let exp = match expected {
        Value::String(s) => s.as_str(),
        Value::Number(_) => return false,
        Value::Bool(_) => return false,
    };

    match op {
        CompOp::Eq => actual.eq_ignore_ascii_case(exp),
        CompOp::Ne => !actual.eq_ignore_ascii_case(exp),
        CompOp::Contains => actual.to_lowercase().contains(&exp.to_lowercase()),
        _ => false,
    }
}

fn compare_num(actual: u64, op: &CompOp, expected: &Value) -> bool {
    let exp = match expected {
        Value::Number(n) => *n,
        Value::String(s) => {
            if let Ok(n) = s.parse::<u64>() {
                n
            } else {
                return false;
            }
        }
        Value::Bool(_) => return false,
    };

    match op {
        CompOp::Eq => actual == exp,
        CompOp::Ne => actual != exp,
        CompOp::Gt => actual > exp,
        CompOp::Lt => actual < exp,
        CompOp::Gte => actual >= exp,
        CompOp::Lte => actual <= exp,
        _ => false,
    }
}

fn compare_bool(actual: bool, op: &CompOp, expected: &Value) -> bool {
    let exp = match expected {
        Value::Bool(b) => *b,
        Value::String(s) => s.eq_ignore_ascii_case("true") || s == "1",
        Value::Number(n) => *n != 0,
    };

    match op {
        CompOp::Eq => actual == exp,
        CompOp::Ne => actual != exp,
        _ => false,
    }
}

pub fn parse_filter(input: &str) -> Result<Expr, FilterError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(FilterError::SyntaxError {
            position: 0,
            message: "Empty filter expression".to_string(),
        });
    }
    let tokens = tokenize(trimmed)?;
    let mut parser = Parser::new(tokens);
    parser.parse()
}
