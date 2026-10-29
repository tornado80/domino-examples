; Both games are stateless and only differ in CPAReal versus CPA in real mode.
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
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "kia"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "kia")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "kix"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "kix")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "koa"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "koa")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri1"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri1")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri2"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri2")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri3"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri3")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ri4"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri4")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ro1"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ro1")))
                 (and (= sample-id-left  (sample-id "ReceiverReductionOuter" "GetView" "ro2"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ro2")))
                 (and (= sample-id-left  (sample-id "CPAReal" "Enc" "k"))
                      (= sample-id-right (sample-id "CPA" "Enc" "k")))
                 (and (= sample-id-left  (sample-id "CPAReal" "Enc" "r0"))
                      (= sample-id-right (sample-id "CPA" "Enc" "r0")))
                 (and (= sample-id-left  (sample-id "CPAReal" "Enc" "r1"))
                      (= sample-id-right (sample-id "CPA" "Enc" "r1")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))))
)

(define-state-relation invariant (left right)
    true
)
