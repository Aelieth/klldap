use gloo_timers::callback::Timeout;
use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct StatusModalProps {
    pub message: String,
    pub is_success: bool,
    pub on_dismiss: Callback<()>,
}

#[function_component(StatusModal)]
pub fn status_modal(props: &StatusModalProps) -> Html {
    let on_dismiss = props.on_dismiss.clone();

    // Auto-dismiss after 4 seconds
    use_effect(move || {
        let timeout = Timeout::new(4000, move || {
            on_dismiss.emit(());
        });
        move || {
            timeout.cancel();
        }
    });

    let bg_class = if props.is_success {
        "bg-success"
    } else {
        "bg-danger"
    };

    html! {
        <div
            class="modal fade show d-block"
            tabindex="-1"
            style="z-index: 1070; background: rgba(0, 0, 0, 0.4);"
            onclick={props.on_dismiss.reform(|_| ())}>
            <div class="modal-dialog modal-dialog-centered modal-sm" onclick={|e: MouseEvent| e.stop_propagation()}>
                <div class="modal-content border-0 shadow">
                    <div class={format!("modal-body text-center text-white p-4 {}", bg_class)}>
                        <i class={if props.is_success { "bi bi-check-circle-fill fs-1 mb-3" } else { "bi bi-x-circle-fill fs-1 mb-3" }}></i>
                        <h5 class="mb-3">{ &props.message }</h5>
                        <small class="opacity-75">{"Click anywhere to dismiss"}</small>
                    </div>
                </div>
            </div>
        </div>
    }
}
