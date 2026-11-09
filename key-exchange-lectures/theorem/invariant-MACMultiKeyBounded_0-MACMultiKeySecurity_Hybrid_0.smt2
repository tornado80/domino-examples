;; Hop 0: the bounded multi-key game with real Verify is the hybrid at i = n_real
;; with the single-key game real. Every key is at position n_real + kid > i, so
;; the single-key game is never used and every key stays locally real.

(define-fun randomness-mapping-MAC_Gen
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "MACMultiKey" "MAC_Gen" "psk"))
         (= sample-id-right (sample-id "MACHybridReduction" "MAC_Gen" "psk"))))

(define-fun randomness-mapping-MAC_Corrupt
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-MAC_Mac
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-MAC_Verify
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-state-relation counters (l r)
    (and (= l.KeyBound.count r.KeyBound.count)
         (= l.MACMultiKey.kid_ctr r.MACHybridReduction.kid_ctr)
         (>= r.MACHybridReduction.kid_ctr 0)))

(define-state-relation keys-equal (l r)
    (= l.MACMultiKey.K r.MACHybridReduction.K))

(define-state-relation single-unused (l r)
    (and (= r.MACHybridReduction.i r.MACHybridReduction.n_real)
         ((_ is mk-none) r.MACSingleKey.k)))

(define-state-relation no-low-keys (l r)
    (forall ((kid Int))
        (=> (<= kid 0)
            ((_ is mk-none) (select r.MACHybridReduction.K kid)))))

(define-state-relation invariant (l r)
    (and (counters l r)
         (keys-equal l r)
         (single-unused l r)
         (no-low-keys l r)))
