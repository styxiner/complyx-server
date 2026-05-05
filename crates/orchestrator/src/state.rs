//! Estados en memoria de los agentes registrados.
//!
//! El `Orchestrator` mantiene en un `DashMap` el estado en tiempo real de cada agente: Cuando hizo
//! su ultimo contacto y si esta online u offline.
//!
//! Prefiero usar DashMap porque tiene un sharding interno que permite escrituras concurrentes en
//! distintas entradas sin tener un lock global.
//! Usar un `Mutex<HashMap>` normal sería un cuello de botella porque solo un agente podría
//! actualizar su heartbeat a la vez. Por lo que con decenas o cientos de agentes haciendo poll
//! de forma simultanea, enlentecería muchísimo todo el flujo de comunicación.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub enum AgentStatus {
    Online,
    Offline,
}

#[derive(Debug, Clone)]
pub struct AgentState {
    pub last_seen: Instant,
    pub last_policy_hash: Option<String>, // Hash del bundle de politicas que el agente tiene en
    // cache. `None` si el agente aun no ha hecho poll
    // exitoso.
    pub status: AgentStatus,
}

impl AgentState {
    /// Crea un estado nuevo marcando al agente como online ahora mismo.
    pub fn new_online() -> Self {
        Self {
            last_seen: Instant::now(),
            last_policy_hash: None,
            status: AgentStatus::Online,
        }
    }
}

// Orquestador de agentes.
//
// Es barato de clonar: internamente usa `Arc` para compartir el estado entre el servicio gRPC y
// el heartbeat monitor.
#[derive(Clone)]
pub struct Orchestrator {
    agents: Arc<DashMap<Uuid, AgentState>>,
    offline_timeout: Duration, // Segundos sin heartbeat tras los que un agente se considera offline.
}

impl Orchestrator {
    // Crea un nuevo orquestador.
    //
    // Argumentos
    //
    // * `offline_timeout_secs` — segundos sin actividad para marcar un agente offline.
    //   Uso 2-3 veces el `heartbeat_interval` del agente por dar algo de margen.
    pub fn new(offline_timeout_secs: u64) -> Self {
        Self {
            agents: Arc::new(DashMap::new()),
            offline_timeout: Duration::from_secs(offline_timeout_secs),
        }
    }

    // Registra un heartbeat o poll de un agente, actualizando `last_seen`.
    //
    // Si el agente no estaba en el mapa (primer contacto tras el enrolamiento), se inserta con
    // estado `Online`
    pub fn update_heartbeat(&self, agent_id: Uuid) {
        self.agents
            .entry(agent_id)
            .and_modify(|s| {
                s.last_seen = Instant::now();
                s.status = AgentStatus::Online;
            })
            .or_insert_with(AgentState::new_online);

        tracing::debug!(agent_id = %agent_id, "heartbeat registrado");
    }

    // Actualiza el hash del bundle que el agente tiene en caché.
    //
    // Se llama cuando el agente envía un `PollRequest` con su hash actual. Permite al
    // `policy-distributor` detectar si necesita transmitir el bundle.
    pub fn update_policy_hash(&self, agent_id: Uuid, hash: String) {
        if let Some(mut state) = self.agents.get_mut(&agent_id) {
            state.last_policy_hash = Some(hash);
        }
    }

    // Marca un agente como offline explícitamente. Llamado por el heatbeat monitor cuando detecta
    // timeout.
    pub fn mark_offline(&self, agent_id: Uuid) {
        //        if let Some(mut state) = self.agents.get_mut(&agent_id) {
        //            if state.status != AgentStatus::Offline {
        //                tracing::warn!(
        //                    agent_id = %agent_id,
        //                    last_seen_secs = state.last_seen.elapsed().as_secs(),
        //                    "agente marcado como offline por timeout"
        //                );
        //                state.status = AgentStatus::Offline;
        //            }
        //        }
        //
        //  Clippy recomendaba colapsar: collapsable_if
        if let Some(mut state) = self.agents.get_mut(&agent_id)
            && state.status != AgentStatus::Offline
        {
            tracing::warn!(
                agent_id = %agent_id,
                last_seen_secs = state.last_seen.elapsed().as_secs(),
                "agente marcado como offline por timeout"
            );
            state.status = AgentStatus::Offline;
        }
    }

    // Elimina el estado de un agente del mapa.
    // Se llama cuando el agente es desregistrado o revocado.
    pub fn remove_agent(&self, agent_id: Uuid) {
        self.agents.remove(&agent_id);
        tracing::info!(agent_id = %agent_id, "agente eliminado del orchestrator");
    }

    // Devuelve el estado actual de un agente, o `None` si no está en el mapa.
    pub fn get_state(&self, agent_id: Uuid) -> Option<AgentState> {
        self.agents.get(&agent_id).map(|s| s.clone())
    }

    // Devuelve el hash del bundle que el agente tiene en caché. Cadena vacia si el agente no tiene
    // hash registrado.
    pub fn get_policy_hash(&self, agent_id: Uuid) -> String {
        self.agents
            .get(&agent_id)
            .and_then(|s| s.last_policy_hash.clone())
            .unwrap_or_default()
    }

    /// Lista los UUIDs de todos los agentes online.
    pub fn list_online(&self) -> Vec<Uuid> {
        self.agents
            .iter()
            .filter(|e| e.value().status == AgentStatus::Online)
            .map(|e| *e.key())
            .collect()
    }

    /// Número total de agentes conocidos (online + offline).
    pub fn total_count(&self) -> usize {
        self.agents.len()
    }

    /// Número de agentes online.
    pub fn online_count(&self) -> usize {
        self.agents
            .iter()
            .filter(|e| e.value().status == AgentStatus::Online)
            .count()
    }

    /// Devuelve el timeout configurado para el heartbeat monitor.
    pub fn offline_timeout(&self) -> Duration {
        self.offline_timeout
    }

    /// Devuelve los agentes que han superado el timeout sin heartbeat. Usado por el heatbeat
    /// monitor para saber cual marcar `Offline`
    pub fn stale_agents(&self) -> Vec<Uuid> {
        self.agents
            .iter()
            .filter(|e| {
                e.value().status == AgentStatus::Online
                    && e.value().last_seen.elapsed() > self.offline_timeout
            })
            .map(|e| *e.key())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_orchestrator() -> Orchestrator {
        Orchestrator::new(300)
    }

    #[test]
    fn update_heartbeat_inserts_new_agent() {
        let orc = make_orchestrator();
        let id = Uuid::new_v4();

        assert!(orc.get_state(id).is_none());
        orc.update_heartbeat(id);
        assert!(orc.get_state(id).is_some());
        assert_eq!(orc.get_state(id).unwrap().status, AgentStatus::Online);
    }

    #[test]
    fn mark_offline_changes_status() {
        let orc = make_orchestrator();
        let id = Uuid::new_v4();

        orc.update_heartbeat(id);
        assert_eq!(orc.get_state(id).unwrap().status, AgentStatus::Online);

        orc.mark_offline(id);
        assert_eq!(orc.get_state(id).unwrap().status, AgentStatus::Offline);
    }

    #[test]
    fn update_heartbeat_brings_back_online() {
        let orc = make_orchestrator();
        let id = Uuid::new_v4();

        orc.update_heartbeat(id);
        orc.mark_offline(id);
        assert_eq!(orc.get_state(id).unwrap().status, AgentStatus::Offline);

        // Nuevo heartbeat → vuelve a Online
        orc.update_heartbeat(id);
        assert_eq!(orc.get_state(id).unwrap().status, AgentStatus::Online);
    }

    #[test]
    fn update_policy_hash_stores_hash() {
        let orc = make_orchestrator();
        let id = Uuid::new_v4();

        orc.update_heartbeat(id);
        assert_eq!(orc.get_policy_hash(id), "");

        orc.update_policy_hash(id, "abc123".to_string());
        assert_eq!(orc.get_policy_hash(id), "abc123");
    }

    #[test]
    fn remove_agent_clears_state() {
        let orc = make_orchestrator();
        let id = Uuid::new_v4();

        orc.update_heartbeat(id);
        assert!(orc.get_state(id).is_some());

        orc.remove_agent(id);
        assert!(orc.get_state(id).is_none());
    }

    #[test]
    fn online_count_counts_only_online() {
        let orc = make_orchestrator();
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();

        orc.update_heartbeat(id1);
        orc.update_heartbeat(id2);
        orc.update_heartbeat(id3);
        orc.mark_offline(id3);

        assert_eq!(orc.online_count(), 2);
        assert_eq!(orc.total_count(), 3);
    }

    #[test]
    fn stale_agents_with_zero_timeout_marks_all() {
        // Con timeout = 0, cualquier agente que no acaba de hacer heartbeat es stale
        let orc = Orchestrator::new(0);
        let id = Uuid::new_v4();

        orc.update_heartbeat(id);
        // Pequeña pausa para que elapsed() > 0
        std::thread::sleep(Duration::from_millis(1));

        let stale = orc.stale_agents();
        assert!(stale.contains(&id));
    }
}
