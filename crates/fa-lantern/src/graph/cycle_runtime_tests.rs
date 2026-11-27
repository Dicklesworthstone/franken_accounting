//! Integration of the std-only temporal search with the Lantern work meter.

use super::cycles::{self, Error, test_edge as edge};

#[test]
fn runtime_budget_interrupts_recursion_and_discards_already_found_cycles() {
    let edges = [
        edge(1, 10, 20, 1),
        edge(2, 20, 10, 2),
        edge(3, 30, 40, 3),
        edge(4, 40, 50, 4),
        edge(5, 50, 30, 5),
    ];
    let complete = cycles::find(&edges, 3, 10, 100, &mut || {
        Ok::<(), core::convert::Infallible>(())
    })
    .unwrap();
    assert_eq!(complete.paths, vec![vec![0, 1], vec![2, 3, 4]]);

    // Four steps have already found the first cycle and entered the
    // second. The fifth charge must stop the recursive extension, not
    // return that first motif as an apparently complete result.
    let mut meter = crate::Meter::new("graph.round_trips", Some(4), None);
    let result = cycles::find(&edges, 3, 10, 100, &mut || meter.compare(1));
    assert!(matches!(
        result,
        Err(Error::Interrupted(crate::LanternError::BudgetExhausted {
            used: 5,
            budget: 4,
            ..
        }))
    ));
    assert_eq!(meter.work().comparisons, 5);
    assert!(8 > meter.work().comparisons);

    // No lost or duplicated work charge on a successful search.
    let mut meter = crate::Meter::new("graph.round_trips", Some(8), None);
    let metered = cycles::find(&edges, 3, 10, 100, &mut || meter.compare(1)).unwrap();
    assert_eq!(metered, complete);
    // Five roots plus one and two continuations in the two cycles.
    assert_eq!(meter.work().comparisons, 8);
}

#[test]
fn runtime_cancellation_is_observed_within_recursive_search_interval() {
    use std::cell::Cell;

    struct Flag<'a>(&'a Cell<bool>);
    impl crate::Cancellation for Flag<'_> {
        fn cancelled(&self) -> bool {
            self.0.get()
        }
    }

    // One root has many chronological continuations, with no completing
    // cycle. Cancellation therefore has to be consulted within extend(),
    // before this root's entire search returns to the outer loop.
    let mut edges = vec![edge(1, 10, 20, 1)];
    edges.extend((2..2_100).map(|id| edge(id, 20, 30, 2)));
    let mut complete_steps = 0u64;
    let complete = cycles::find(&edges, 3, 10, 10_000, &mut || {
        complete_steps += 1;
        Ok::<(), core::convert::Infallible>(())
    })
    .unwrap();
    assert!(complete.paths.is_empty());
    let cancel = Cell::new(false);
    let flag = Flag(&cancel);
    let mut meter = crate::Meter::new("graph.round_trips", None, Some(&flag));
    let mut visited = 0u64;
    let result = cycles::find(&edges, 3, 10, 10_000, &mut || {
        visited += 1;
        if visited == 5 {
            cancel.set(true);
        }
        meter.compare(1)
    });
    let Err(Error::Interrupted(crate::LanternError::Cancelled { used, .. })) = result else {
        panic!("the recursive search did not propagate cancellation: {result:?}");
    };
    assert!((5..=5 + crate::CANCELLATION_INTERVAL).contains(&used));
    assert_eq!(visited, used);
    assert_eq!(meter.work().comparisons, used);
    assert!(used < 2_099, "the first root was still being searched");
    assert!(used < complete_steps);
}
