//! stream 模块：SSE / NDJSON 流式还原（M7）。
//!
//! - `sse`：SSE 分帧 + 事件改写 + 跨 chunk 扣留 + 聚合转发
//! - `slots`：三大协议的增量文本槽位识别（对齐 Python `_sse_text_slots`）

pub mod slots;
pub mod sse;
