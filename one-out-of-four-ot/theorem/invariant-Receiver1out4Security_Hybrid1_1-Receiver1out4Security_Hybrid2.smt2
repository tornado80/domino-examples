; Both games are stateless. Inner keys and randomness are renamed from row/column
; indices to active/inactive, and the key and randomness of column (not bo) of the
; outer encryptions move to the CPA game, so the mapping depends on bi and bo.
(define-fun randomness-mapping-GetView
    (
        (sample-id-left SampleId)
        (sample-id-right SampleId)
        (sample-ctr-left Int)
        (sample-ctr-right Int)
    )
    Bool
    (let ((bi (el2-1 (el2-2 <arg-Receiver1out4Security_Hybrid1-GetView-inputs>)))
          (bo (el2-2 (el2-2 <arg-Receiver1out4Security_Hybrid1-GetView-inputs>))))
    (or
        (and (= sample-ctr-left 0)
             (= sample-ctr-right 0)
             (or
                 ; inner keys: the CPA key of the inner scheme becomes the inactive inner key
                 (and (= sample-id-left  (sample-id "ReceiverReductionInner" "GetView" "kia"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "kia")))
                 (and (= sample-id-left  (sample-id "CPA" "Enc" "k"))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "kix")))
                 ; inner randomness: cells (bi, bo), (not bi, bo), (bi, not bo), (not bi, not bo)
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverReductionInner" "GetView" "ria1") (sample-id "ReceiverReductionInner" "GetView" "ria0")))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri1")))
                 (and (= sample-id-left  (ite bo (sample-id "CPA" "Enc" "r1") (sample-id "CPA" "Enc" "r0")))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri2")))
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverReductionInner" "GetView" "ria0") (sample-id "ReceiverReductionInner" "GetView" "ria1")))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri3")))
                 (and (= sample-id-left  (ite bo (sample-id "CPA" "Enc" "r0") (sample-id "CPA" "Enc" "r1")))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ri4")))
                 ; outer keys: ko_bo is the active key, ko_(not bo) the CPA key
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverReductionInner" "GetView" "ko1") (sample-id "ReceiverReductionInner" "GetView" "ko0")))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "koa")))
                 (and (= sample-id-left  (ite bo (sample-id "ReceiverReductionInner" "GetView" "ko0") (sample-id "ReceiverReductionInner" "GetView" "ko1")))
                      (= sample-id-right (sample-id "CPAReal" "Enc" "k")))
                 ; outer randomness: column bo in the reduction, column (not bo) in the CPA game
                 (and (= sample-id-left  (ite bi (ite bo (sample-id "ReceiverReductionInner" "GetView" "ro4") (sample-id "ReceiverReductionInner" "GetView" "ro3")) (ite bo (sample-id "ReceiverReductionInner" "GetView" "ro2") (sample-id "ReceiverReductionInner" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ro1")))
                 (and (= sample-id-left  (ite (not bi) (ite bo (sample-id "ReceiverReductionInner" "GetView" "ro4") (sample-id "ReceiverReductionInner" "GetView" "ro3")) (ite bo (sample-id "ReceiverReductionInner" "GetView" "ro2") (sample-id "ReceiverReductionInner" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "ReceiverReductionOuter" "GetView" "ro2")))
                 (and (= sample-id-left  (ite bi (ite (not bo) (sample-id "ReceiverReductionInner" "GetView" "ro4") (sample-id "ReceiverReductionInner" "GetView" "ro3")) (ite (not bo) (sample-id "ReceiverReductionInner" "GetView" "ro2") (sample-id "ReceiverReductionInner" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "CPAReal" "Enc" "r0")))
                 (and (= sample-id-left  (ite (not bi) (ite (not bo) (sample-id "ReceiverReductionInner" "GetView" "ro4") (sample-id "ReceiverReductionInner" "GetView" "ro3")) (ite (not bo) (sample-id "ReceiverReductionInner" "GetView" "ro2") (sample-id "ReceiverReductionInner" "GetView" "ro1"))))
                      (= sample-id-right (sample-id "CPAReal" "Enc" "r1")))))
        ; the 1-out-of-2 simulator's randomness, once per 1-out-of-2 instance
        (and (= sample-ctr-left sample-ctr-right)
             (= sample-id-left  (sample-id "ReceiverSim1out2" "GetSimView" "rsim"))
             (= sample-id-right (sample-id "ReceiverSim1out2" "GetSimView" "rsim")))))
)

(define-state-relation invariant (left right)
    true
)
