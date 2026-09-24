//! mask 模块：规则引擎 + 占位符 + 会话 + JSON 树管线（M3-M5）。
//!
//! - `placeholder`：占位符生成/解析/正则族（对齐 Python `_PLACEHOLDER_RX` 等）
//! - `validators`：Luhn/身份证/IBAN/JWT/USCC 等 11 类语义校验器
//! - `rules`：21 类内置规则（D7 环视下沉为 BoundaryCheck）
//! - `session`：会话映射 + TTL 复用表 + 后缀索引
//! - `exemptions`：路径感知豁免表 + 业务区判定 + 键名白名单
//! - `tree`：mask_tree / restore_tree（M4）
//! - `engine`：mask()/restore() 编排（M5）

pub mod engine;
pub mod exemptions;
pub mod placeholder;
pub mod rules;
pub mod session;
pub mod tree;
pub mod validators;
