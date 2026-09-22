//! shadow-core/session: 实时连接会话监控器与状态追踪
//!
//! 记录活动与历史连接（时间、目标、规则、动作、上下行流量、状态），
//! 提供轻量高效的环形队列存储与瞬时速率统计。

use crate::router::RouteAction;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// 会话生命周期状态
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// 活跃传输中
    Active,
    /// 正常关闭
    Closed,
    /// 规则阻断
    Blocked,
    /// 失败或异常断开
    Failed,
}

impl std::fmt::Display for SessionStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStatus::Active => write!(f, "ACTIVE"),
            SessionStatus::Closed => write!(f, "CLOSED"),
            SessionStatus::Blocked => write!(f, "BLOCKED"),
            SessionStatus::Failed => write!(f, "FAILED"),
        }
    }
}

/// 会话记录
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SessionRecord {
    pub id: u64,
    pub start_time: u64,
    pub time_str: String,
    pub target: String,
    pub rule_name: String,
    pub action: RouteAction,
    pub status: SessionStatus,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub duration_ms: u64,
}

/// 活跃会话上下文
struct ActiveContext {
    created_at: Instant,
    record: SessionRecord,
}

/// 速率快照
struct SpeedSnapshot {
    last_check: Instant,
    last_up: u64,
    last_down: u64,
    speed_up_bps: u64,
    speed_down_bps: u64,
}

/// 实时会话追踪器
pub struct SessionTracker {
    next_id: AtomicU64,
    max_history: usize,
    history: RwLock<VecDeque<SessionRecord>>,
    active: RwLock<HashMap<u64, ActiveContext>>,
    total_up: AtomicU64,
    total_down: AtomicU64,
    speed: Mutex<SpeedSnapshot>,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new(200)
    }
}

impl SessionTracker {
    pub fn new(max_history: usize) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            max_history,
            history: RwLock::new(VecDeque::with_capacity(max_history)),
            active: RwLock::new(HashMap::new()),
            total_up: AtomicU64::new(0),
            total_down: AtomicU64::new(0),
            speed: Mutex::new(SpeedSnapshot {
                last_check: Instant::now(),
                last_up: 0,
                last_down: 0,
                speed_up_bps: 0,
                speed_down_bps: 0,
            }),
        }
    }

    /// 开启新会话并返回会话唯一 ID
    pub fn start_session(
        &self,
        target: &str,
        rule_name: &str,
        action: RouteAction,
        is_blocked: bool,
    ) -> u64 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 格式化当前时间为 HH:MM:SS
        let time_str = format_current_time();

        let initial_status = if is_blocked {
            SessionStatus::Blocked
        } else {
            SessionStatus::Active
        };

        let record = SessionRecord {
            id,
            start_time: now_sec,
            time_str,
            target: target.to_string(),
            rule_name: rule_name.to_string(),
            action,
            status: initial_status,
            upload_bytes: 0,
            download_bytes: 0,
            duration_ms: 0,
        };

        if is_blocked {
            // 被阻断的直接进历史队列，不驻留 active 表
            let mut hist = self.history.write().unwrap();
            if hist.len() >= self.max_history {
                hist.pop_front();
            }
            hist.push_back(record);
        } else {
            let mut act = self.active.write().unwrap();
            act.insert(
                id,
                ActiveContext {
                    created_at: Instant::now(),
                    record,
                },
            );
        }

        id
    }

    /// 更新会话上传与下载流量
    pub fn record_traffic(&self, id: u64, up: u64, down: u64) {
        self.total_up.fetch_add(up, Ordering::Relaxed);
        self.total_down.fetch_add(down, Ordering::Relaxed);

        let mut act = self.active.write().unwrap();
        if let Some(ctx) = act.get_mut(&id) {
            ctx.record.upload_bytes += up;
            ctx.record.download_bytes += down;
        }
    }

    /// 结束会话并归档至历史队列
    pub fn finish_session(&self, id: u64, status: SessionStatus, up: u64, down: u64) {
        self.total_up.fetch_add(up, Ordering::Relaxed);
        self.total_down.fetch_add(down, Ordering::Relaxed);

        let removed = {
            let mut act = self.active.write().unwrap();
            act.remove(&id)
        };

        if let Some(mut ctx) = removed {
            ctx.record.upload_bytes += up;
            ctx.record.download_bytes += down;
            ctx.record.status = status;
            ctx.record.duration_ms = ctx.created_at.elapsed().as_millis() as u64;

            let mut hist = self.history.write().unwrap();
            if hist.len() >= self.max_history {
                hist.pop_front();
            }
            hist.push_back(ctx.record);
        }
    }

    /// 获取会话列表（活跃中的置前，历史记录倒序）
    pub fn list_sessions(&self, limit: usize) -> Vec<SessionRecord> {
        let mut result = Vec::new();

        // 1. 活跃会话 (动态更新耗时)
        {
            let act = self.active.read().unwrap();
            for ctx in act.values() {
                let mut rec = ctx.record.clone();
                rec.duration_ms = ctx.created_at.elapsed().as_millis() as u64;
                result.push(rec);
            }
        }

        // 2. 历史会话 (最新发生在前)
        {
            let hist = self.history.read().unwrap();
            for rec in hist.iter().rev() {
                if result.len() >= limit {
                    break;
                }
                result.push(rec.clone());
            }
        }

        if result.len() > limit {
            result.truncate(limit);
        }
        result
    }

    /// 获取当前瞬时速率 (上行 B/s, 下行 B/s) 与累计字节数 (总上行, 总下行)
    pub fn speed_and_totals(&self) -> (u64, u64, u64, u64) {
        let cur_up = self.total_up.load(Ordering::Relaxed);
        let cur_down = self.total_down.load(Ordering::Relaxed);

        let mut speed_lock = self.speed.lock().unwrap();
        let elapsed = speed_lock.last_check.elapsed();

        if elapsed >= Duration::from_millis(500) {
            let delta_sec = elapsed.as_secs_f64().max(0.001);
            let delta_up = cur_up.saturating_sub(speed_lock.last_up);
            let delta_down = cur_down.saturating_sub(speed_lock.last_down);

            speed_lock.speed_up_bps = (delta_up as f64 / delta_sec) as u64;
            speed_lock.speed_down_bps = (delta_down as f64 / delta_sec) as u64;

            speed_lock.last_check = Instant::now();
            speed_lock.last_up = cur_up;
            speed_lock.last_down = cur_down;
        }

        (
            speed_lock.speed_up_bps,
            speed_lock.speed_down_bps,
            cur_up,
            cur_down,
        )
    }

    /// 清空所有历史会话
    pub fn clear(&self) {
        let mut hist = self.history.write().unwrap();
        hist.clear();
    }
}

fn format_current_time() -> String {
    #[cfg(windows)]
    {
        #[repr(C)]
        struct SystemTimeWin {
            w_year: u16,
            w_month: u16,
            w_day_of_week: u16,
            w_day: u16,
            w_hour: u16,
            w_minute: u16,
            w_second: u16,
            w_milliseconds: u16,
        }
        extern "system" {
            fn GetLocalTime(lp_system_time: *mut SystemTimeWin);
        }
        let mut st = std::mem::MaybeUninit::<SystemTimeWin>::uninit();
        unsafe {
            GetLocalTime(st.as_mut_ptr());
            let st = st.assume_init();
            format!("{:02}:{:02}:{:02}", st.w_hour, st.w_minute, st.w_second)
        }
    }
    #[cfg(not(windows))]
    {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sec = now % 60;
        let min = (now / 60) % 60;
        let hour = (now / 3600) % 24;
        format!("{:02}:{:02}:{:02}", hour, min, sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle_and_ring_buffer() {
        let tracker = SessionTracker::new(3);

        // 1. 启动一个活跃会话
        let sid1 = tracker.start_session(
            "github.com:443",
            "默认代理",
            RouteAction::Proxy,
            false,
        );
        assert_eq!(sid1, 1);

        // 记录流量
        tracker.record_traffic(sid1, 1024, 4096);

        // 查看列表应该包含 1 条活跃会话
        let list1 = tracker.list_sessions(10);
        assert_eq!(list1.len(), 1);
        assert_eq!(list1[0].status, SessionStatus::Active);
        assert_eq!(list1[0].upload_bytes, 1024);
        assert_eq!(list1[0].download_bytes, 4096);

        // 关闭会话 1
        tracker.finish_session(sid1, SessionStatus::Closed, 500, 1000);

        // 2. 插入 3 个阻断会话，验证环形队列上限为 3
        for i in 2..=4 {
            tracker.start_session(
                &format!("bad-site-{}.com:80", i),
                "阻断恶意网站",
                RouteAction::Block,
                true,
            );
        }

        let list2 = tracker.list_sessions(10);
        // 上限 3 条历史记录
        assert_eq!(list2.len(), 3);
        // 最新的在最前
        assert_eq!(list2[0].target, "bad-site-4.com:80");
        assert_eq!(list2[0].status, SessionStatus::Blocked);
    }
}
