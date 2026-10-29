; Both games are stateless. The CPA game's key and randomness become the inactive
; outer key and the randomness of column (not bo); the inner encryptions of
; column (not bo) the reduction still computes are discarded.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 ; keys
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "kia"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kia")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "kix"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kix")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "koa"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "koa")))
                 (and (= sample-id-left  (sample-id "CPA" "Enc" "k"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "kox")))
                 ; randomness
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri1"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ri1")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri2"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ri2")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ro1"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro1")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ro2"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro2")))
                 (and (= sample-id-left  (sample-id "CPA" "Enc" "r0"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro3")))
                 (and (= sample-id-left  (sample-id "CPA" "Enc" "r1"))
                      (= sample-id-right (sample-id "ReceiverSim1out4" "GetSimView" "ro4")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))))
)

(define-state-relation invariant (left right)
    true
)
