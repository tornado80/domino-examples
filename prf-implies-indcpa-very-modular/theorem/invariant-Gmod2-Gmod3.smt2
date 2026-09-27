; Both sides abort on a nonce collision. Without one, the nonce is fresh, so
; the lazily sampled PRF value on the left is a fresh draw, like the XOR pad.
(define-fun randomness-mapping-Enc
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (and
        (= sample-ctr-left 0)
        (= sample-ctr-right 0)
        (or
            (and (= sample-id-left  (sample-id "Nonce" "Sample" "nonce"))
                 (= sample-id-right (sample-id "Nonce" "Sample" "nonce")))
            (and (= sample-id-left  (sample-id "Prf" "Eval" "r"))
                 (= sample-id-right (sample-id "Xor" "Xor" "pad")))))
)

(define-state-relation invariant (left right)
    (and
        (= left.Nonce.T right.Nonce.T)
        ; pads only exist for nonces that were already drawn
        (forall ((x Bits_256))
            (=> (not (is-mk-none (select left.Prf.T x)))
                (not (is-mk-none (select left.Nonce.T x)))))))
