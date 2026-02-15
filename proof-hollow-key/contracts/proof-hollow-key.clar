;; ProofHollowKey - Zero-Knowledge Identity Verification System
;; A simplified implementation of hollow key generation and claim verification

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-insufficient-stake (err u103))
(define-constant err-unauthorized (err u104))
(define-constant err-invalid-claim (err u105))

;; Minimum stake required for validators (in microSTX)
(define-constant min-validator-stake u1000000)

;; Data Variables
(define-data-var claim-nonce uint u0)

;; Data Maps

;; Hollow Keys: Maps user principal to their hollow key hash
(define-map hollow-keys
    principal
    {
        key-hash: (buff 32),
        created-at: uint,
        reputation-score: uint,
        active: bool
    }
)

;; Claims: Maps claim ID to claim details
(define-map claims
    uint
    {
        claimer: principal,
        claim-type: (string-ascii 50),
        claim-hash: (buff 32),
        verified: bool,
        attestations: uint,
        created-at: uint
    }
)

;; Validators: Maps validator principal to stake and status
(define-map validators
    principal
    {
        stake-amount: uint,
        attestation-count: uint,
        active: bool,
        registered-at: uint
    }
)

;; Attestations: Maps claim ID and validator to attestation status
(define-map attestations
    {claim-id: uint, validator: principal}
    {
        attested: bool,
        timestamp: uint
    }
)

;; Read-only functions

(define-read-only (get-hollow-key (user principal))
    (map-get? hollow-keys user)
)

(define-read-only (get-claim (claim-id uint))
    (map-get? claims claim-id)
)

(define-read-only (get-validator (validator principal))
    (map-get? validators validator)
)

(define-read-only (get-attestation (claim-id uint) (validator principal))
    (map-get? attestations {claim-id: claim-id, validator: validator})
)

(define-read-only (get-reputation-score (user principal))
    (match (map-get? hollow-keys user)
        hollow-key (ok (get reputation-score hollow-key))
        (err err-not-found)
    )
)

;; Public functions

;; Register a hollow key for identity verification
(define-public (register-hollow-key (key-hash (buff 32)))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (is-none (map-get? hollow-keys caller)) err-already-exists)
        (ok (map-set hollow-keys caller
            {
                key-hash: key-hash,
                created-at: block-height,
                reputation-score: u0,
                active: true
            }
        ))
    )
)

;; Register as a validator by staking tokens
(define-public (register-validator (stake-amount uint))
    (let
        (
            (caller tx-sender)
        )
        (asserts! (>= stake-amount min-validator-stake) err-insufficient-stake)
        (asserts! (is-none (map-get? validators caller)) err-already-exists)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? stake-amount caller (as-contract tx-sender)))
        
        (ok (map-set validators caller
            {
                stake-amount: stake-amount,
                attestation-count: u0,
                active: true,
                registered-at: block-height
            }
        ))
    )
)

;; Submit a claim for verification
(define-public (submit-claim (claim-type (string-ascii 50)) (claim-hash (buff 32)))
    (let
        (
            (caller tx-sender)
            (new-claim-id (+ (var-get claim-nonce) u1))
        )
        ;; Verify user has a hollow key
        (asserts! (is-some (map-get? hollow-keys caller)) err-not-found)
        
        ;; Create new claim
        (map-set claims new-claim-id
            {
                claimer: caller,
                claim-type: claim-type,
                claim-hash: claim-hash,
                verified: false,
                attestations: u0,
                created-at: block-height
            }
        )
        
        ;; Increment nonce
        (var-set claim-nonce new-claim-id)
        (ok new-claim-id)
    )
)

;; Attest to a claim as a validator
(define-public (attest-claim (claim-id uint))
    (let
        (
            (caller tx-sender)
            (claim-data (unwrap! (map-get? claims claim-id) err-not-found))
            (validator-data (unwrap! (map-get? validators caller) err-unauthorized))
            (current-attestations (get attestations claim-data))
        )
        ;; Verify validator is active
        (asserts! (get active validator-data) err-unauthorized)
        
        ;; Check if already attested
        (asserts! (is-none (map-get? attestations {claim-id: claim-id, validator: caller})) 
            err-already-exists)
        
        ;; Record attestation
        (map-set attestations {claim-id: claim-id, validator: caller}
            {
                attested: true,
                timestamp: block-height
            }
        )
        
        ;; Update claim with new attestation count
        (map-set claims claim-id
            (merge claim-data {attestations: (+ current-attestations u1)})
        )
        
        ;; Update validator attestation count
        (map-set validators caller
            (merge validator-data 
                {attestation-count: (+ (get attestation-count validator-data) u1)}
            )
        )
        
        (ok true)
    )
)

;; Verify a claim (requires minimum 3 attestations)
(define-public (verify-claim (claim-id uint))
    (let
        (
            (claim-data (unwrap! (map-get? claims claim-id) err-not-found))
            (claimer (get claimer claim-data))
            (hollow-key-data (unwrap! (map-get? hollow-keys claimer) err-not-found))
        )
        ;; Check if claim has enough attestations (minimum 3)
        (asserts! (>= (get attestations claim-data) u3) err-invalid-claim)
        
        ;; Mark claim as verified
        (map-set claims claim-id
            (merge claim-data {verified: true})
        )
        
        ;; Increase reputation score
        (map-set hollow-keys claimer
            (merge hollow-key-data 
                {reputation-score: (+ (get reputation-score hollow-key-data) u10)}
            )
        )
        
        (ok true)
    )
)

;; Deactivate hollow key
(define-public (deactivate-hollow-key)
    (let
        (
            (caller tx-sender)
            (hollow-key-data (unwrap! (map-get? hollow-keys caller) err-not-found))
        )
        (ok (map-set hollow-keys caller
            (merge hollow-key-data {active: false})
        ))
    )
)

;; Withdraw validator stake (only if no recent attestations)
(define-public (withdraw-validator-stake)
    (let
        (
            (caller tx-sender)
            (validator-data (unwrap! (map-get? validators caller) err-not-found))
            (stake-amount (get stake-amount validator-data))
        )
        ;; Deactivate validator
        (map-set validators caller
            (merge validator-data {active: false})
        )
        
        ;; Return stake
        (as-contract (stx-transfer? stake-amount tx-sender caller))
    )
)