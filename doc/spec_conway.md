Conway update for HW wallets

This document describes changes for Ledger and Trezor devices (HW wallets). Only a subset of the features will be implemented on certain devices:

Trezor:
* C (stake key registration/deregistration with deposit),
* D (delegation to dreps)

Nano S:
* C (stake key registration/deregistration with deposit),
* D (delegation to dreps)

Ledger full:
* A, B, C, D, F, G, H, I (everything except combined certificates)

Requirements (feature on the left requires features on the right):
* B -> A
* G -> A

Sample transactions containing the new elements: [https://auspicious-fuchsia-2e9.notion.site/Transactions-in-SanchoNet-fbcf91c799404fe4b30a78e8e091df79](https://auspicious-fuchsia-2e9.notion.site/Transactions-in-SanchoNet-fbcf91c799404fe4b30a78e8e091df79)

# **A. New key derivation schemas**

For all the new key schemas, we will allow export of such public keys. However, since they are derivable from the
account key, HW wallets will not expect these to be exported individually, similarly to payment and stake keys.

The key derivation paths and bech32 prefixes are described in [CIP-0105](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0105/README.md).

The previous experience shows that new use cases could appear for required signers where users want to include keys
that are not directly related to the transaction body. Since there is no harm possible in including a key in that field,
we will allow it for all the new key derivation schemas.

Witnesses corresponding to new key derivation paths (DRep, constitutional committee) will always be shown
(in line with what is currently implemented for 1853 stake pool operator keys).

### **DRep key**

According to [CIP-0105](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0105/README.md),
the derivation path for DRep keys is

    m / 1852' / 1815' / account' / 3 / address_index.

These keys can only be used in witnesses, certificates requiring drep_credential (see B) and in required signers.

It is "strongly suggested" in CIP-0105 that only the value 0 should be used for address_index, but it is not strictly
forbidden. HW wallets will allow non-zero non-hardened values, but if such a path is used as a witness,
they will display a warning.

### **Constitutional committee hot and cold keys**

According to [CIP-0105](https://github.com/cardano-foundation/CIPs/blob/master/CIP-0105/README.md), the derivation path
for committee keys is

    m / 1852' / 1815' / account' / 4 / address_index    for hot keys,
    m / 1852' / 1815' / account' / 5 / address_index    for cold keys.

These keys can only be used in constitutional committee certificates and voting (see F and G) and in required signers.

It is "strongly suggested" in CIP-0105 that only the value 0 should be used for address_index, but it is not strictly
forbidden. HW wallets will allow non-zero non-hardened values, but if such a path is used as a witness,
they will display a warning.

# **New certificates**

*Note:* the existing Ledger code dealing with certificates is somewhat fragile and difficult to maintain, especially
given the changes that arose with the addition of Stax UI. Before adding the new certificates, we will think it through
and come up with a better design that will include the new certificates, with focus on minimizing needless repetition.

**Credentials in certificates**

Various types of credentials are described in the CDDL by the same structure.

    credential =
      [  0, addr_keyhash
      // 1, scripthash
      ]

stake_credential = credential
drep_credential = credential
committee_cold_credential = credential
committee_hot_credential = credential

For the purpose of HW wallets, addr_keyhash can be described by a key derivation path in addition to giving
the hash directly. If only the hash is given, the user might be unaware that the key belongs to him,
which introduces security hazards (e.g. unwittingly witnessing a certificate). Consequently, certain types of
credentials are forbidden for certain types of certificates, depending on other items in the transaction body --
the intent of the user is described by a so-called transaction signing mode and there is lots of code describing
[security policies](https://github.com/vacuumlabs/ledger-app-cardano-shelley/blob/develop/src/securityPolicy.c)
related to this. This will have to be updated to reflect the new certificates, which will require some thought,
so it is not fully discussed in this document now.

### **B. DRep registration, retirement, update**

    reg_drep_cert = (16, drep_credential, coin, anchor / null)
    unreg_drep_cert = (17, drep_credential, coin)
    update_drep_cert = (18, drep_credential, anchor / null)

    anchor =
      [ anchor_url       : url
      , anchor_data_hash : $hash32
      ]

Options for drep_credential depending on signing mode:
ORDINARY_TX: key path (DRep key only), script hash
MULTISIG_TX: script hash
PLUTUS_TX: key path (DRep key only), key hash, script hash
POOL_REGISTRATION_*: not allowed

(The reason why we do not allow key hash for ordinary transactions: the user cannot determine
from which key the hash is computed, i.e. he could inadvertently sign a certificate when
several such certificates are present in the transaction.)

UI texts for new certificate items: "Deposit", "Anchor URL", "Anchor hash".
For DRep credential, we will mimic the existing implementation of stake credential.
If the anchor is null, we replace the two anchor details screens with a single one saying "No anchor".

[Example transactions](https://auspicious-fuchsia-2e9.notion.site/Transactions-in-SanchoNet-fbcf91c799404fe4b30a78e8e091df79)
with DRep certificates from SanchoNet.

### **C. Stake registration and deregistration with explicit deposit**

    reg_cert = (7, stake_credential, coin)
    unreg_cert = (8, stake_credential, coin)

UI texts for certificate items: "Deposit"
(for stake credential, existing implementation will be used)

Security policies etc. the same as for the existing stake registration and deregistration.

### **D. Delegation to DReps**

    vote_deleg_cert = (9, stake_credential, drep)

    drep =
      [ 0, addr_keyhash
      // 1, scripthash
      // 2  ; always abstain
      // 3  ; always no confidence
      ]

### **E. Combined certificates**

***These won't be supported on HW wallets because it adds unnecessary complications without much benefit. (In the future, we might consider adding them to at least some of the devices.)***

    stake_vote_deleg_cert = (10, stake_credential, pool_keyhash, drep)
    stake_reg_deleg_cert = (11, stake_credential, pool_keyhash, coin)
    vote_reg_deleg_cert = (12, stake_credential, drep, coin)
    stake_vote_reg_deleg_cert = (13, stake_credential, pool_keyhash, drep, coin)

### **F. Constitutional committee certificates**

    auth_committee_hot_cert = (14, committee_cold_credential, committee_hot_credential)
    resign_committee_cold_cert = (15, committee_cold_credential, anchor / null)

    committee_cold_credential = committee_hot_credential =
      [  0, addr_keyhash
      // 1, scripthash
      ]

These certificates are allowed in all types of transactions except pool registrations (as determined by the signing mode).

For the keys used in credentials, new derivation paths will be added (see A).

The cold key must be given by derivation path, not just the key hash -- otherwise the user cannot determine
from which key the hash is computed, i.e. he could inadvertently sign a certificate
(when several such certificates are present in the transaction).

For the hot key, key hash should be allowed (voting might be governed by a key not stored in the HW wallet).

# **G. Voting**

There are 3 types of voters: constitutional committee members, DReps, and staking pool operators.
Since anyone can become a DRep, voting needs to be supported.

*NOTE: The following section describes the historical situation where Nano S had to be supported and time to implement it was limited. Since 2026, there are no longer such limitations, and the app aims to support this feature in full.*

The typical use case is a single voter voting for a single action. It is also unlikely that the voting transaction will
contain unnecessary elements not related to item 19. If we allow only a single voter casting a single vote per transaction
on HW wallets, the users get the full functionality; the only disadvantage compared to full support would be slightly
higher transaction costs when several votes are split into separate transactions. On the other hand, it would lead
to a great simplification in the code for HW wallets, significantly cutting development time and costs.
(If it turns out in the future that we do need several votes per transaction within HW wallets,
the implementation can be extended.)
There is also a security advantage: if several voters are allowed, it is impossible for a HW wallet to match witnesses
to voters, so a single witness signature might sign several votes without the user being aware of it.

Voting will be included in all types of transactions except pool registrations. All DRep keys, stake pool operator keys
and committee member keys are shown if used to witness a transaction. Stake pool operator keys are not used elsewhere in
the transaction (because pool registrations are excluded); committee hot keys are only used for voting;
DRep keys can be used for both voting and in the registration/deregistration certificate, but those elements are
always shown, so the user will be fully aware of their presence in the transaction.

    , ? 19 : voting_procedures        ; New; Voting procedures

    voting_procedures = { + voter => { + gov_action_id => voting_procedure } }

    ; Constitutional Committee Hot KeyHash: 0
    ; Constitutional Committee Hot ScriptHash: 1
    ; DRep KeyHash: 2
    ; DRep ScriptHash: 3
    ; StakingPool KeyHash: 4
    voter =
      [ 0, addr_keyhash
      // 1, scripthash
      // 2, addr_keyhash
      // 3, scripthash
      // 4, addr_keyhash
      ]

    gov_action_id =
      [ transaction_id   : $hash32
      , gov_action_index : uint
      ]

    voting_procedure =
      [ vote
      , anchor / null
      ]

    ; no - 0
    ; yes - 1
    ; abstain - 2
    vote = 0 .. 2

    anchor =
      [ anchor_url       : url
      , anchor_data_hash : $hash32
      ]

UI flow (screens for Nano S), assuming a single vote per tx:

1. "Voting" / "procedure"
2. "Voter" / voter
3. "Action tx hash" / gov_action_id.transaction_id
4. "Action tx index" / gov_action_id.gov_action_index
5. "Vote" / vote -- "no", "yes", "abstain"
6. "Anchor URL" / anchor_url
7. "Anchor hash" / anchor_data_hash
   (6. and 7. are replaced with a single screen if anchor is null saying "No anchor")

# **H. Treasury and donations**

There are two additional transaction body items.

    , ? 21 : coin                     ; New; current treasury value
    , ? 22 : positive_coin            ; New; donation

These items are straightforward to implement. They can be part of any transaction and will always be displayed.

UI text: "Treasury amount" for item 21, "Donation" for item 22

# **I. Governance actions**

**Status: implemented.** See `doc/PROPOSAL_PROCEDURES_DESIGN.md` for the data model, the
file layout and the test plan. The reservations below no longer block the feature, but they
did shape its scope: `cost_models` (protocol_param_update key 18) is rejected for exactly the
reason given here, because a device screen cannot show it in a reviewable form. The other 29
keys are parsed and displayed.

    , ? 20 : [* proposal_procedure]   ; New; Proposal procedures

Unsuitable for HW wallets. Too complex, hard to display meaningfully on a small screen,
might require Plutus script redeemers etc.

On the other hand, only a small transaction fee and temporarily the deposit are in danger, so HW wallet security is
rather an overkill (considering the hassle of signing such transactions on HW wallets).
