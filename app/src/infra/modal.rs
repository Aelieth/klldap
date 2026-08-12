#![allow(clippy::empty_docs)]

use wasm_bindgen::prelude::*;
use yew::NodeRef;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = bootstrap)]
    pub type Modal;

    #[wasm_bindgen(constructor, js_namespace = bootstrap)]
    pub fn new(e: web_sys::Element) -> Modal;

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn show(this: &Modal);

    #[wasm_bindgen(method, js_namespace = bootstrap)]
    pub fn hide(this: &Modal);
}

/// Owns a Bootstrap modal and the `NodeRef` it binds to. Components hold one of
/// these instead of a `(NodeRef, Option<Modal>)` pair: attach `node_ref()` to the
/// modal element, call `init_on_first_render` from `rendered`, then `show`/`hide`.
#[derive(Default)]
pub struct ModalHandle {
    node_ref: NodeRef,
    modal: Option<Modal>,
}

impl ModalHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_ref(&self) -> NodeRef {
        self.node_ref.clone()
    }

    pub fn init_on_first_render(&mut self, first_render: bool) {
        if first_render {
            self.modal = Some(Modal::new(
                self.node_ref
                    .cast::<web_sys::Element>()
                    .expect("Modal node is not an element"),
            ));
        }
    }

    pub fn show(&self) {
        if let Some(modal) = &self.modal {
            modal.show();
        }
    }

    pub fn hide(&self) {
        if let Some(modal) = &self.modal {
            modal.hide();
        }
    }
}
