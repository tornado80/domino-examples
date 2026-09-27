; Both sides abort on a nonce collision. Without one, the nonce is fresh, so
; the lazily sampled pad on the left is a fresh draw, like the XOR pad.
(define-fun randomness-mapping-ENC
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
            (and (= sample-id-left  (sample-id "Coll" "GET" "x"))
                 (= sample-id-right (sample-id "Coll" "GET" "x")))
            (and (= sample-id-left  (sample-id "Reduction2" "ENC" "pad"))
                 (= sample-id-right (sample-id "XOR" "XOR" "pad")))))
)

(define-state-relation invariant (left right)
    (and
        (= left.Coll.T right.Coll.T)
        ; pads only exist for nonces that were already drawn
        (forall ((x Bits_256))
            (=> (not (is-mk-none (select left.Reduction2.T x)))
                (not (is-mk-none (select left.Coll.T x)))))))
