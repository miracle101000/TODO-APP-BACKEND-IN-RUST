use std::{collections::HashMap, sync::Arc};
use parking_lot::Mutex;
use tokio::sync::broadcast::{Sender};

use crate::models::todo::TodoItem;



#[derive(Clone)]
pub struct AppState {
    pub todo_list: Arc<Mutex<Vec<TodoItem>>>,
    pub tx: Sender<TodoItem>,
    pub refresh_tokens: Arc<Mutex<HashMap<String,String>>>,
    pub users: Arc<Mutex<HashMap<String,String>>>,
}

