//! shadow-injector: 进程启动挂起、双架构 PE 判定与 DLL 注入器 CLI 模块

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "shadow-injector",
    author,
    version,
    about = "ShadowProxy 双架构专用注入执行器"
)]
struct Args {
    /// 目标可执行文件路径 (挂起创建并注入)
    #[arg(short, long)]
    target: Option<PathBuf>,

    /// 待注入的 Hook 动态库路径
    #[arg(short, long)]
    dll: PathBuf,

    /// 目标程序启动命令行参数
    #[arg(short, long, allow_hyphen_values = true)]
    args: Option<String>,

    /// 已运行中的目标进程 PID (直接附加注入)
    #[arg(short, long)]
    pid: Option<u32>,
}

fn main() {
    let args = Args::parse();

    if let Some(pid) = args.pid {
        match shadow_injector::inject_existing_pid(pid, &args.dll) {
            Ok(()) => {
                println!("OK: {}", pid);
            }
            Err(e) => {
                eprintln!("附加注入 PID {} 失败: {}", pid, e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref target) = args.target {
        let cmd_args = args.args.as_deref().filter(|s| !s.trim().is_empty());
        match shadow_injector::spawn_and_inject_with_args(target, &args.dll, cmd_args) {
            Ok(pid) => {
                println!("PID: {}", pid);
            }
            Err(e) => {
                eprintln!("启动并注入目标程序 {:?} 失败: {}", target, e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("参数错误: 必须指定 --target 或 --pid");
        std::process::exit(2);
    }
}
