//! Monitor de heartbeats en segundo plano.
//!
//! Arranca una tarea `tokio::spawn` que periodicamente:
//!
//! Detecta agentes que no han hecho heartbeat en mas de `offline_timeout`
//! Los marca offline en el `Orchestrator` (estado en memoria)
//! No actualiza la bbdd: `latest_connectin` se actualiza en cada heartbeat/poll real desde
//! `db::agents::update_latest_connection`. El monitor solo gestiona el estado en memoria para que
//! en la API y web muestre online/offline en tiempo real sin consultar la bbdd en cada request.

//use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

use crate::state::Orchestrator;

// Arranca el monitor de heartbeats como tarea en segundo plano.
//
// Argumentos:
//
// * `orchestrator`: estado compartido de los agentes
// * `check_interval`: con que frecuencia el monitor busca agentes stale.
// * `shutdown_rx`: receptor del canal de parada. Cuando recibe `true`, el monitor termina
// limpiamente.
//
// ## Ejemplo
// ```ignore
// let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
//
// spawn_monitor(
//     orchestrator.clone(),
//     Duration::from_secs(60),
//     shutdown_rx,
// );
//
// // Para parar el monitor:
// shutdown_tx.send(true).unwrap();
// ```

pub fn spawn_monitor(
    orchestrator: Orchestrator,
    check_interval: Duration,
    mut shutdown_rx: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(
            check_interval_secs = check_interval.as_secs(),
            offline_timeout_secs = orchestrator.offline_timeout().as_secs(),
            "heartbeat monitor arrancado"
        );

        let mut interval = tokio::time::interval(check_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("heartbeat monitor detenido");
                        break;
                    }
                }

                _ = interval.tick() => {
                        run_check(&orchestrator);
                    }
            }
        }
    })
}

// Ejecuta un ciclo de comprobacion: detecta y marca agente stale.
pub fn run_check(orchestrator: &Orchestrator) {
    let stale = orchestrator.stale_agents();

    if stale.is_empty() {
        tracing::debug!(
            online = orchestrator.online_count(),
            total = orchestrator.total_count(),
            "heartbeat check: todos los agentes activos"
        );
        return;
    }

    tracing::info!(
        stale_count = stale.len(),
        online = orchestrator.online_count(),
        total = orchestrator.total_count(),
        "heartbeat check: marcando agentes offline"
    );

    for agent_id in stale {
        orchestrator.mark_offline(agent_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AgentStatus;
    use uuid::Uuid;

    #[tokio::test]
    async fn monitor_marks_stale_agents_offline() {
        let orc = Orchestrator::new(0); // timeout = 0 → cualquier agente es stale inmediatamente
        let id = Uuid::new_v4();
        orc.update_heartbeat(id);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = spawn_monitor(
            orc.clone(),
            Duration::from_millis(10), // check cada 10ms para el test
            shutdown_rx,
        );

        // Esperar un tick
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Parar el monitor
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        assert_eq!(
            orc.get_state(id).unwrap().status,
            AgentStatus::Offline,
            "el agente debe estar offline tras superar el timeout"
        );
    }

    #[tokio::test]
    async fn monitor_does_not_mark_active_agents_offline() {
        let orc = Orchestrator::new(300); // timeout generoso
        let id = Uuid::new_v4();
        orc.update_heartbeat(id);

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = spawn_monitor(orc.clone(), Duration::from_millis(10), shutdown_rx);

        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();

        assert_eq!(
            orc.get_state(id).unwrap().status,
            AgentStatus::Online,
            "el agente no debe estar offline si no ha superado el timeout"
        );
    }

    #[tokio::test]
    async fn monitor_stops_cleanly_on_shutdown() {
        let orc = Orchestrator::new(300);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let handle = spawn_monitor(orc, Duration::from_secs(60), shutdown_rx);

        shutdown_tx.send(true).unwrap();

        // El monitor debe terminar sin bloquearse
        tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("el monitor no terminó en 1 segundo")
            .unwrap();
    }
}
