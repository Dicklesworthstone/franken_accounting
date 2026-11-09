# Sales invoices with inventory relief

`fa invoice` can recognize the sale and its cost of goods sold in one native
`PostBatch`. The ordinary invoice debits the customer's receivable and credits
revenue. Each independent inventory source contributes a native lot disposal
that credits its quantity and carrying cost, debits the declared quantity offset,
and debits the declared COGS account. All entries publish together or none do.

## Declare the accounting routes

The inventory account must already have its native lot policy and retained
acquisitions. The party, accounts and units must exist. A stock line explicitly
names every route; `item` and `product` remain descriptive memo words.

```sh
fa invoice --book ./books/myco \
  --party CUSTOMER --number INV-10442 --date 2026-03-15 \
  --receivable 1200 --revenue 4000 \
  --line 'qty=3 unit_price="25.00 USD" inventory=1400 quantity_unit=SHARE quantity_offset=1499 cost_offset=5100 lot_law=FIFO item=WIDGET' \
  --line 'amount="15.00 USD" description=delivery' \
  --evidence D:<retained-document-oid> --dry-run --plan-out invoice.plan --json
```

`qty` is a positive whole number. The same quantity extends the sales price and
relieves stock at the quantity unit's registered scale. `quantity_unit` must be a
balanced noncurrency unit. Stock lines require `qty` and `unit_price`; a separate
`amount` is refused. Service lines retain the ordinary invoice grammar.

`lot_law` must equal the source account's retained native policy. The supported
laws are `FIFO`, `LIFO`, `SpecificId` and `WeightedAverage`. For `SpecificId`, add
an ordered selection of acquisition entry identities and quantity-leg ordinals:

```text
lots=0123456789abcdef0123456789abcdef:0,fedcba9876543210fedcba9876543210:2
```

Other laws refuse `lots`. Acquisition costs determine relief; the sales price
never supplies COGS. Every arithmetic operation uses the native exact units and
cost-flow laws. An optional `--entity` carries through to each disposal's complete
dimensions, and the source history must match those dimensions.

## Review and publish one transaction

The dry run emits `batch_plan`, including every exact reviewed member. Commit
the saved plan with the same acting principal and capability:

```sh
fa commit --book ./books/myco --plan invoice.plan --grant read --json
```

Direct source derivation requires current `read` and `post` authority. Without
`--dry-run`, an authorized interactive invoice posts the same atomic batch and
emits `batch_posted`. Bound Agent execution retains the ordinary rehearsal-only
behavior. Planning reserves no stock. An intervening publication invalidates a
saved plan, so prepare a fresh one before a first commit at a changed snapshot.

Repeated lines for one inventory account are grouped into one disposal when
their quantity unit, complete dimensions, offset accounts, law and ordered lot
selection all agree. Their quantities are added with overflow checks. Conflicting
contracts refuse the whole invoice. Different inventory accounts create distinct
disposal members; their offsets cannot touch another participating source. The
invoice's receivable and revenue legs also cannot touch those sources.

These restrictions come from the existing native batch independence law. They
prevent one member from changing another member's reviewed cost basis. Any
insufficient stock, invalid source, route conflict, authority refusal or stale
plan leaves both revenue and inventory unpublished.

## Drafts and exact retries

Use `--draft <name>` to append the invoice and every disposal under one retained
draft planning record. A Post-only Agent confined to its own draft can prepare
these source-bound entries without receiving general book-read authority. An
independent authorized principal reviews and promotes the draft; promotion
checks the retained source history and publishes the unchanged entries together.
Stock movement that changes a reviewed source makes promotion refuse atomically.
Inventory invoices do not support counterfactual `--scenario` disposal.

The invoice retains its normal `invoice:[<entity>:]<number>` key, or the explicit
`--key`. Separate domain-separated, bounded keys identify the batch and each
source disposal, including when the invoice key already uses the native maximum
length. Retry with the complete original request and the same acting principal.
An exact retry returns the original publication even after stock exhaustion or
later acquisitions; it does not reprice COGS from today's inventory. A retained
draft retry reuses its original reviewed disposal basis, including after draft
promotion or discard. Changing the invoice or relief contract under the same key
refuses rather than posting another sale. Saved batch plans are also retryable
after their successful publication.

The executable regression scenarios are in
`crates/fa-cli/tests/cli/lot_disposal/invoice.rs`.
