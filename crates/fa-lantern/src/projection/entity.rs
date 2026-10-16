//! Legal-entity normalization for an admitted journal population. The kernel
//! requires every leg in a multi-entity book to name its entity; a book with
//! only one entity may mix explicit and implicit mentions of that entity.
//! This helper never guesses from account identity, amount, or chronology.

use std::collections::BTreeSet;

#[derive(Clone, Debug, Default)]
pub(crate) struct Scope {
    named: BTreeSet<u128>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MissingEntity;

impl Scope {
    pub(crate) fn observe(&mut self, entity: Option<u128>) {
        if let Some(entity) = entity {
            self.named.insert(entity);
        }
    }

    pub(crate) fn resolve(&self, entity: Option<u128>) -> Result<Option<u128>, MissingEntity> {
        match (entity, self.named.len()) {
            (Some(entity), _) => Ok(Some(entity)),
            (None, 0) => Ok(None),
            (None, 1) => Ok(self.named.first().copied()),
            (None, _) => Err(MissingEntity),
        }
    }
}

/// The single native-unit/entity coordinate selected by a source entry's
/// inflow legs. Mixed sources must be refused rather than arbitrarily picking
/// the first entity or pooling claimants across entities.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Source {
    selected: Option<(u32, Option<u128>)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AmbiguousSource {
    Unit,
    Entity,
}

impl Source {
    pub(crate) fn observe(
        &mut self,
        unit: u32,
        entity: Option<u128>,
    ) -> Result<(), AmbiguousSource> {
        match self.selected {
            None => self.selected = Some((unit, entity)),
            Some((previous, _)) if previous != unit => return Err(AmbiguousSource::Unit),
            Some((_, previous)) if previous != entity => return Err(AmbiguousSource::Entity),
            Some(_) => {}
        }
        Ok(())
    }

    pub(crate) fn selected(self) -> Option<(u32, Option<u128>)> {
        self.selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entirely_implicit_book_keeps_its_own_scope() {
        let mut scope = Scope::default();
        scope.observe(None);
        assert_eq!(scope.resolve(None), Ok(None));
    }

    #[test]
    fn one_declared_entity_normalizes_implicit_and_explicit_mentions() {
        let mut scope = Scope::default();
        for value in [None, Some(42), None, Some(42)] {
            scope.observe(value);
        }
        assert_eq!(scope.resolve(None), Ok(Some(42)));
        assert_eq!(scope.resolve(Some(42)), Ok(Some(42)));
    }

    #[test]
    fn multiple_entities_never_share_implicit_movements() {
        let mut scope = Scope::default();
        scope.observe(Some(7));
        scope.observe(Some(9));
        assert_eq!(scope.resolve(Some(7)), Ok(Some(7)));
        assert_eq!(scope.resolve(Some(9)), Ok(Some(9)));
        assert_eq!(scope.resolve(None), Err(MissingEntity));
    }

    #[test]
    fn scope_resolution_is_permutation_invariant() {
        for values in [
            vec![],
            vec![None, Some(0), Some(0)],
            vec![Some(u128::MAX), Some(0), None],
        ] {
            let mut forward = Scope::default();
            let mut backward = Scope::default();
            for value in &values {
                forward.observe(*value);
            }
            for value in values.iter().rev() {
                backward.observe(*value);
            }
            for value in [None, Some(0), Some(u128::MAX)] {
                assert_eq!(forward.resolve(value), backward.resolve(value));
            }
        }
    }

    #[test]
    fn repeated_source_legs_keep_one_resolved_coordinate() {
        let mut source = Source::default();
        assert_eq!(source.selected(), None);
        source.observe(7, Some(42)).unwrap();
        source.observe(7, Some(42)).unwrap();
        assert_eq!(source.selected(), Some((7, Some(42))));
    }

    #[test]
    fn a_source_spanning_entities_is_refused_without_overwriting_its_first_coordinate() {
        let mut source = Source::default();
        source.observe(7, Some(1)).unwrap();
        assert_eq!(source.observe(7, Some(2)), Err(AmbiguousSource::Entity));
        assert_eq!(source.selected(), Some((7, Some(1))));
    }

    #[test]
    fn a_source_spanning_units_is_refused_even_within_one_entity() {
        let mut source = Source::default();
        source.observe(7, Some(1)).unwrap();
        assert_eq!(source.observe(8, Some(1)), Err(AmbiguousSource::Unit));
        assert_eq!(source.selected(), Some((7, Some(1))));
    }
}
