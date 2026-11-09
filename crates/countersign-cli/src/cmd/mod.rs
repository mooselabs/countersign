//! One module per command group.

pub mod audit;
pub mod doctor;
pub mod grants;
pub mod hide;
pub mod import;
pub mod mutate;
pub mod reveal;
pub mod run;
pub mod secrets;
pub mod session;

use crate::cli::{AuditCommand, Command, SessionCommand};
use crate::error::CnError;
use crate::output::{Ctx, Done};

/// Runs every command except `run`, which has its own exit codes.
pub fn dispatch(ctx: &Ctx, command: Command) -> Result<Done, CnError> {
    match command {
        Command::List(args) => secrets::list(ctx, &args),
        Command::Show { name } => secrets::show(ctx, &name),
        Command::Request(args) => grants::request(ctx, &args),
        Command::Approve(args) => grants::approve(ctx, &args),
        Command::Deny(args) => grants::deny(ctx, &args),
        Command::Grants(args) => grants::grants(ctx, &args),
        Command::Revoke(args) => grants::revoke(ctx, &args),
        Command::Hide(args) => hide::hide(ctx, &args),
        Command::Reveal(args) => reveal::reveal(ctx, &args),
        Command::Add(args) => mutate::add(ctx, &args),
        Command::Set(args) => mutate::set(ctx, &args),
        Command::Edit(args) => mutate::edit(ctx, &args),
        Command::Rm(args) => mutate::rm(ctx, &args),
        Command::Import(args) => import::import(ctx, &args),
        Command::Session(args) => match args.command {
            None => session::show(ctx),
            Some(SessionCommand::Exec { label, command }) => {
                session::exec(ctx, label.as_deref(), &command)
            }
        },
        Command::Audit(args) => match args.command {
            None => audit::query(ctx, &args.query),
            Some(AuditCommand::Verify(v)) => audit::verify(ctx, &v),
            Some(AuditCommand::Checkpoints(_)) => Err(CnError::later("cn audit checkpoints")),
            Some(AuditCommand::Pubkey(_)) => Err(CnError::later("cn audit pubkey")),
        },
        Command::Doctor => doctor::doctor(ctx),
        Command::Export(_) => Err(CnError::later("cn export")),
        Command::Unlock(_) => Err(CnError::later("cn unlock (FIDO2 store unlock)")),
        Command::Approver(_) => Err(CnError::later("cn approver (FIDO2 approvers)")),
        Command::Sudo(_) => Err(CnError::later("cn sudo")),
        Command::Run(_) => unreachable!("cn run is dispatched by main"),
    }
}
