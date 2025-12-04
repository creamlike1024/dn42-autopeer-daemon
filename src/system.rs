use anyhow::{Ok, Result, anyhow};
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
    if CONFIG.env.init_system == "systemd" {
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
    } else if CONFIG.env.init_system == "openrc" {
        // ln -s /etc/init.d/wg-quick /etc/init.d/wg-quick.interface_name
        let item = format!("wg-quick.{}", interface_name);
        let link_file_path = format!("/etc/init.d/{}", item.as_str());
        let args = vec!["-s", "/etc/init.d/wg-quick", &link_file_path];
        let output = Command::new("ln").args(&args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to create symbolic link: {}", stderr));
        }

        // rc-service wg-quick.interface_name start
        let args = vec![&item, "start"];
        let output = Command::new(&CONFIG.env.rc_service_path)
            .args(&args)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to start service: {}", stderr));
        }

        // rc-update add wg-quick.interface_name default
        let args = vec!["add", &item, "default"];
        let output = Command::new(&CONFIG.env.rc_update_path)
            .args(&args)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to add service to default runlevel: {}",
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
    } else {
        Err(anyhow!(
            "Unsupported init system: {}",
            CONFIG.env.init_system
        ))
    }
}

pub fn remove_config(
    interface_name: &str,
    wg_config_path: &str,
    bird_config_path: &str,
) -> Result<()> {
    let _guard = SYSTEM_OP_LOCK
        .lock()
        .map_err(|e| anyhow!("Mutex lock error: {}", e))?;
    if CONFIG.env.init_system == "systemd" {
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
    } else if CONFIG.env.init_system == "openrc" {
        let item = format!("wg-quick.{}", interface_name);
        // rc-service wg-quick.interface_name stop
        let args = vec![&item, "stop"];
        let output = Command::new(&CONFIG.env.rc_service_path)
            .args(&args)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to stop service: {}", stderr));
        }

        // rc-update del wg-quick.interface_name default
        let args = vec!["del", &item, "default"];
        let output = Command::new(&CONFIG.env.rc_update_path)
            .args(&args)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "Failed to remove service from default runlevel: {}",
                stderr
            ));
        }

        // delete /etc/init.d/wg-quick.interface_name
        let link_file_path = format!("/etc/init.d/{}", item.as_str());
        delete(&link_file_path)?;

        // delete config files
        delete_config(wg_config_path, bird_config_path)?;

        // birdc configure
        let args = vec!["configure"];
        let output = Command::new(&CONFIG.env.birdc_path).args(&args).output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("Failed to reconfigure bird daemon: {}", stderr));
        }

        Ok(())
    } else {
        Err(anyhow!(
            "Unsupported init system: {}",
            CONFIG.env.init_system
        ))
    }
}
