;; Hop 0: KX2_b == Model2Security_Hybrid0_b_0_0.
;; Pure refactoring: the KEM package is replaced by two instances of
;; KEMCollisions without aborts. The model is literally the same.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEM" "KEM_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMCollisions_lt" "Coll_Gen" "kem_kgen"))))

(define-fun randomness-mapping-Corrupt
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-NewSession
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send1
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (or (and (= sample-id-left (sample-id "KEM" "KEM_Gen" "kem_kgen")) (= sample-id-right (sample-id "KEMCollisions_eph" "Coll_Gen" "kem_kgen")))
             (and (= sample-id-left (sample-id "KEM" "KEM_Encaps" "kem_encaps")) (= sample-id-right (sample-id "KEMCollisions_lt" "Coll_Encaps" "kem_encaps"))))))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEM" "KEM_Encaps" "kem_encaps"))
         (= sample-id-right (sample-id "KEMCollisions_eph" "Coll_Encaps" "kem_encaps"))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Reveal
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Test
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0) (= sample-ctr-right 0)
         (= sample-id-left (sample-id "Model2" "Test" "test"))
         (= sample-id-right (sample-id "Model2" "Test" "test"))))

(define-state-relation invariant (l r)
    (= l.Model2 r.Model2))
