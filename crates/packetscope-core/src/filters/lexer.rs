use crate::errors::FilterError;

#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    Ident(String),
    Number(u64),
    StringLit(String),
    Eq,       // ==
    Ne,       // !=
    Gt,       // >
    Lt,       // <
    Gte,      // >=
    Lte,      // <=
    Contains, // contains
    And,      // and or &&
    Or,       // or or ||
    Not,      // not or !
    LParen,   // (
    RParen,   // )
}

#[derive(Debug, Clone)]
pub struct SpannedToken {
    pub token: Token,
    pub start: usize,
    pub end: usize,
}

pub fn tokenize(input: &str) -> Result<Vec<SpannedToken>, FilterError> {
    if input.len() > 1000 {
        return Err(FilterError::ExpressionTooLong(1000));
    }

    let mut tokens = Vec::new();
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c.is_whitespace() {
            i += 1;
            continue;
        }

        let start = i;

        match c {
            '(' => {
                tokens.push(SpannedToken {
                    token: Token::LParen,
                    start,
                    end: i + 1,
                });
                i += 1;
            }
            ')' => {
                tokens.push(SpannedToken {
                    token: Token::RParen,
                    start,
                    end: i + 1,
                });
                i += 1;
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(SpannedToken {
                        token: Token::Eq,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    return Err(FilterError::SyntaxError {
                        position: start,
                        message: "Unexpected '=' (did you mean '=='?)".to_string(),
                    });
                }
            }
            '!' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(SpannedToken {
                        token: Token::Ne,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    tokens.push(SpannedToken {
                        token: Token::Not,
                        start,
                        end: i + 1,
                    });
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(SpannedToken {
                        token: Token::Gte,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    tokens.push(SpannedToken {
                        token: Token::Gt,
                        start,
                        end: i + 1,
                    });
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(SpannedToken {
                        token: Token::Lte,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    tokens.push(SpannedToken {
                        token: Token::Lt,
                        start,
                        end: i + 1,
                    });
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < chars.len() && chars[i + 1] == '&' {
                    tokens.push(SpannedToken {
                        token: Token::And,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    return Err(FilterError::SyntaxError {
                        position: start,
                        message: "Unexpected '&' (did you mean '&&' or 'and'?)".to_string(),
                    });
                }
            }
            '|' => {
                if i + 1 < chars.len() && chars[i + 1] == '|' {
                    tokens.push(SpannedToken {
                        token: Token::Or,
                        start,
                        end: i + 2,
                    });
                    i += 2;
                } else {
                    return Err(FilterError::SyntaxError {
                        position: start,
                        message: "Unexpected '|' (did you mean '||' or 'or'?)".to_string(),
                    });
                }
            }
            '"' | '\'' => {
                let quote = c;
                i += 1;
                let str_start = i;
                while i < chars.len() && chars[i] != quote {
                    i += 1;
                }
                if i >= chars.len() {
                    return Err(FilterError::SyntaxError {
                        position: start,
                        message: "Unterminated string literal".to_string(),
                    });
                }
                let s: String = chars[str_start..i].iter().collect();
                i += 1; // skip closing quote
                tokens.push(SpannedToken {
                    token: Token::StringLit(s),
                    start,
                    end: i,
                });
            }
            _ => {
                if c.is_ascii_digit() {
                    let num_start = i;
                    while i < chars.len() && chars[i].is_ascii_digit() {
                        i += 1;
                    }
                    // Check if it's an IP address like 192.168.1.1
                    if i < chars.len() && (chars[i] == '.' || chars[i] == ':') {
                        while i < chars.len()
                            && (chars[i].is_alphanumeric() || chars[i] == '.' || chars[i] == ':')
                        {
                            i += 1;
                        }
                        let s: String = chars[num_start..i].iter().collect();
                        tokens.push(SpannedToken {
                            token: Token::StringLit(s),
                            start: num_start,
                            end: i,
                        });
                    } else {
                        let num_str: String = chars[num_start..i].iter().collect();
                        let n = num_str
                            .parse::<u64>()
                            .map_err(|_| FilterError::SyntaxError {
                                position: num_start,
                                message: format!("Invalid number literal '{}'", num_str),
                            })?;
                        tokens.push(SpannedToken {
                            token: Token::Number(n),
                            start: num_start,
                            end: i,
                        });
                    }
                } else if c.is_alphabetic() || c == '_' {
                    let ident_start = i;
                    while i < chars.len()
                        && (chars[i].is_alphanumeric() || chars[i] == '_' || chars[i] == '.')
                    {
                        i += 1;
                    }
                    let s: String = chars[ident_start..i].iter().collect();
                    let lower = s.to_lowercase();
                    let token = match lower.as_str() {
                        "and" => Token::And,
                        "or" => Token::Or,
                        "not" => Token::Not,
                        "contains" => Token::Contains,
                        _ => Token::Ident(s),
                    };
                    tokens.push(SpannedToken {
                        token,
                        start: ident_start,
                        end: i,
                    });
                } else {
                    return Err(FilterError::SyntaxError {
                        position: start,
                        message: format!("Unexpected character '{}'", c),
                    });
                }
            }
        }
    }

    Ok(tokens)
}
