mod app;
mod components;
mod pages;
mod routes;
mod state;

use app::App;

fn main() {
    console_error_panic_hook::set_once();
    yew::Renderer::<App>::new().render();
}
