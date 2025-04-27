use std::fmt;

use aya::Ebpf;

use crate::args::Commands;

struct Program {
    name: String,
    program_type: ProgramType,
    tracepoint: String,
    category: Category,
}
#[derive(Default)]
struct ProgramBuilder {
    name: String,
    program_type: ProgramType,
    category: Category,
    tracepoint: String,
}
#[derive(Default)]
enum ProgramType {
    #[default]
    TracePoint,
    Kprobe,
}

#[derive(Default)]
enum Category {
    #[default]
    Syscalls,
    Kprobe,
}

impl ProgramBuilder {
    fn new() -> Self {
        ProgramBuilder {
            name: "waoo".to_string(),
            program_type: ProgramType::TracePoint,
            category: Category::Syscalls,
            tracepoint: "sys_enter_open".to_string(),
        }
    }
    fn name(mut self, name: String) -> Self {
        self.name = name;
        self
    }
    fn program_type(mut self, program_type: ProgramType) -> Self {
        self.program_type = program_type;
        self
    }
    fn category(mut self, category: Category) -> Self {
        self.category = category;
        self
    }
    fn tracepoint(mut self, tracepoint: String) -> Self {
        self.tracepoint = tracepoint;
        self
    }
    fn build(self) -> Program {
        Program {
            name: self.name,
            program_type: self.program_type,
            category: self.category,
            tracepoint: self.tracepoint,
        }
    }
}

impl Program {
    fn attach(self, ebpf: &mut Ebpf) -> anyhow::Result<()> {
        match self.program_type {
            ProgramType::TracePoint => {
                let p: &mut aya::programs::TracePoint =
                    ebpf.program_mut(&self.name).unwrap().try_into()?;
                    p.load()?;
                    p.attach(&self.category.to_string(), &self.tracepoint)?;

            },
            ProgramType::Kprobe => {
                let p: &mut aya::programs::KProbe =
                    ebpf.program_mut(&self.name).unwrap().try_into()?;
                p.load()?;
                p.attach(&self.tracepoint, 0)?;
            }
        };
        // p.load()?;
        // p.attach(&self.category.to_string(), &self.tracepoint)?;
        Ok(())
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Category::Syscalls => write!(f, "syscalls"),
            Category::Kprobe => write!(f, "kprobe"),
        }
    }
}

pub fn attach_program(command: Commands, ebpf: &mut Ebpf) {
    match command {
        Commands::Opensnoop {} => {
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_enter_open".to_string())
                .name("trace_sys_enter_open".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_exit_open".to_string())
                .name("trace_sys_exit_open".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_enter_openat".to_string())
                .name("trace_sys_enter_openat".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_exit_openat".to_string())
                .name("trace_sys_exit_openat".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
        }
        Commands::Killsnoop {} => {
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_enter_kill".to_string())
                .name("trace_enter_kill".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
            ProgramBuilder::new()
                .category(Category::Syscalls)
                .program_type(ProgramType::TracePoint)
                .tracepoint("sys_exit_kill".to_string())
                .name("trace_exit_kill".to_string())
                .build()
                .attach(ebpf)
                .unwrap();
        }
        Commands::Tcpconnect {} => ProgramBuilder::new()
            .category(Category::Kprobe)
            .program_type(ProgramType::Kprobe)
            .tracepoint("tcp_connect".to_string())
            .name("kprobe_tcp_connect".to_string())
            .build()
            .attach(ebpf)
            .unwrap(),
    }
}
