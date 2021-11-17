#[cfg(feature = "exhaustive-tests")]
use swapper::{ecdsa2p::Ecdsa2pContract, Error};

#[test]
#[cfg(feature = "exhaustive-tests")]
fn ecds2p_keygen_sim() {
    use mpecdsa::state_machine::keygen::Keygen;
    use round_based::dev::Simulation;

    let mut sim = Simulation::new();
    sim.enable_benchmarks(false);

    for i in 1..=2 {
        sim.add_party(Keygen::new(i, 1, 2).unwrap());
    }

    let _keys = sim.run().unwrap();
}

#[test]
#[cfg(feature = "exhaustive-tests")]
fn ecdsa2p_contract_keygen_sim() -> Result<(), Error> {
    let mut contracts = [
        Ecdsa2pContract::with_keygen(1)?,
        Ecdsa2pContract::with_keygen(2)?,
    ];
    let mut msgs = vec![];

    for c in contracts.iter_mut() {
        c.keygen_proceed_if_needed()?;
        c.keygen_send_outgoing(&mut msgs)?;
    }

    loop {
        if contracts.iter().all(|c| c.keygen_is_finished()) {
            break;
        }

        let msgs_frozen = msgs.split_off(0);

        for c in contracts.iter_mut() {
            c.keygen_handle_incoming(&msgs_frozen)?;
            c.keygen_send_outgoing(&mut msgs)?;
        }

        for c in contracts.iter_mut() {
            c.keygen_proceed_if_needed()?;
            c.keygen_send_outgoing(&mut msgs)?;
        }
    }

    for c in contracts {
        assert!(c.keygen_is_finished());
    }

    Ok(())
}
