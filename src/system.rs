use anyhow::{Result, anyhow};
use lazy_static::lazy_static;
use std::fs::write;
use std::process::Command;
use std::sync::Mutex as StdMutex;

use crate::CONFIG;

fn save(path: &str, content: &str) -> Result<()> {
    write(path, content)?;
    Ok(())
}

fn delete(path: &str) -> Result<()> {
    std::fs::remove_file(path)?;
    Ok(())
}

fn delete_config(wg_config_path: &str, bird_config_path: &str) -> Result<()> {
    delete(wg_config_path)?;
    delete(bird_config_path)?;
    Ok(())
}

lazy_static! {
    static ref SYSTEM_OP_LOCK: StdMutex<()> = StdMutex::new(());
}

pub fn save_config(
    wg_config_path: &str,
    wg_config: &str,
    bird_config_path: &str,
    bird_config: &str,
) -> Result<()> {
    let _guard = SYSTEM_OP_LOCK
        .lock()
        .map_err(|e| anyhow!("Mutex lock error: {}", e))?;
    save(wg_config_path, wg_config)?;
    save(bird_config_path, bird_config)?;
    Ok(())
}

pub fn apply_config(interface_name: &str) -> Result<()> {
    let _guard = SYSTEM_OP_LOCK
        .lock()
        .map_err(|e| anyhow!("Mutex lock error: {}", e))?;
    let item = format!("wg-quick@{}", interface_name);

    // systemctl start wg-quick@interface_name
    let args = vec!["start", item.as_str()];
    let output = Command::new(&CONFIG.env.systemctl_path)
        .args(&args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to start wireguard tunnel: {}", stderr));
    }

    // systemctl enable wg-quick@interface_name
    let args = vec!["enable", item.as_str()];
    let output = Command::new(&CONFIG.env.systemctl_path)
        .args(&args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "Failed to set starting wireguard tunnel at startup: {}",
            stderr
        ));
    }

    // birdc configure
    let args = vec!["configure"];
    let output = Command::new(&CONFIG.env.birdc_path).args(&args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to reconfigure bird daemon: {}", stderr));
    }

    Ok(())
}

pub fn remove_config(
    interface_name: &str,
    wg_config_path: &str,
    bird_config_path: &str,
) -> Result<()> {
    let _guard = SYSTEM_OP_LOCK
        .lock()
        .map_err(|e| anyhow!("Mutex lock error: {}", e))?;
    let item = format!("wg-quick@{}", interface_name);

    let args = vec!["disable", item.as_str()];
    let output = Command::new(&CONFIG.env.systemctl_path)
        .args(&args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to disable wireguard tunnel: {}", stderr));
    }

    let args = vec!["stop", item.as_str()];
    let output = Command::new(&CONFIG.env.systemctl_path)
        .args(&args)
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to stop wireguard tunnel: {}", stderr));
    }

    delete_config(wg_config_path, bird_config_path)?;

    let args = vec!["configure"];
    let output = Command::new(&CONFIG.env.birdc_path).args(&args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("Failed to reconfigure bird daemon: {}", stderr));
    }

    Ok(())
}
