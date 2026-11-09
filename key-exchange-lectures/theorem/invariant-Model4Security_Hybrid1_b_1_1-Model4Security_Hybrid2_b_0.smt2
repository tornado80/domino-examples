;; Hop 5: Model4Security_Hybrid1_b_1_1 == Model4Security_Hybrid2_b_0.
;; The ideal IND-CCA keys move out of KEMIndCca and into the eager KeyLazy
;; package. Encapsulation to an honest public key stores its key in KeyLazy,
;; and decapsulation of that ciphertext aliases the encapsulator's handle
;; instead of copying the T entry.

(define-fun randomness-mapping-NewKey
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "MACMultiKey" "MAC_Gen" "psk"))
         (= sample-id-right (sample-id "MACMultiKey" "MAC_Gen" "psk"))))

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
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "KEMIndCca" "Ind_Gen" "kem_kgen"))
         (= sample-id-right (sample-id "KEMReductionLazy" "KEM_Gen" "kem_kgen"))))

;; The right side always encapsulates in KEMReductionLazy, the left side only
;; for dishonest public keys, so the mapping reads the old state.
(define-state-relation send2-pk-honest (l r)
    ((_ is mk-some) (select l.KEMReductionIndCca.Hon <arg-Model4Security_Hybrid1-Send2-m1>)))

(define-fun randomness-mapping-Send2
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (ite (send2-pk-honest <<game-state-Model4Security_Hybrid1_b_1_1-old>> <<game-state-Model4Security_Hybrid2_b_0-old>>)
              (or (and (= sample-id-left (sample-id "KEMIndCca" "Ind_Encaps" "kem_encaps"))
                       (= sample-id-right (sample-id "KEMReductionLazy" "KEM_Encaps" "kem_encaps")))
                  (and (= sample-id-left (sample-id "KEMIndCca" "Ind_Encaps" "ideal_key"))
                       (= sample-id-right (sample-id "KeyLazy" "Lazy_Init" "eager_key"))))
              (and (= sample-id-left (sample-id "KEMReductionIndCca" "KEM_Encaps" "kem_encaps"))
                   (= sample-id-right (sample-id "KEMReductionLazy" "KEM_Encaps" "kem_encaps"))))))

(define-fun randomness-mapping-Send3
    ((sample-id-left SampleId) (sample-id-right SampleId)
     (sample-ctr-left Int) (sample-ctr-right Int))
    Bool
    false)

(define-fun randomness-mapping-Send4
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
    (and (= sample-ctr-left 0)
         (= sample-ctr-right 0)
         (= sample-id-left (sample-id "Model4Modular" "Test" "test"))
         (= sample-id-right (sample-id "Model4Modular" "Test" "test"))))

;; The packages above the KEM are literally the same, handles included.
(define-state-relation upper-packages-equal (l r)
    (and (= l.Model4Modular r.Model4Modular)
         (= l.MACMultiKey r.MACMultiKey)))

(define-state-relation kem-tables-equal (l r)
    (and (= l.KEMIndCca.ctr r.KEMReductionLazy.hk_ctr)
         (= l.KEMReductionIndCca.h_ctr r.KEMReductionLazy.h_ctr)
         (= l.KEMIndCca.PK r.KEMReductionLazy.PK)
         (= l.KEMIndCca.SK r.KEMReductionLazy.SK)
         (= l.KEMReductionIndCca.Valid r.KEMReductionLazy.Valid)
         (= l.KEMReductionIndCca.Seen r.KEMReductionLazy.Seen)))

;; PK and SK have the same domain, nothing is stored beyond the counter.
(define-state-relation keypair-shape (l r)
    (forall ((hk Int))
        (and (= ((_ is mk-none) (select l.KEMIndCca.PK hk))
                ((_ is mk-none) (select l.KEMIndCca.SK hk)))
             (=> (> hk l.KEMIndCca.ctr)
                 ((_ is mk-none) (select l.KEMIndCca.PK hk))))))

;; Honest public keys. The Gen aborts make the public key unique per handle.
(define-state-relation hon-agree (l r)
    (and (forall ((pk Bits_lpk))
             (let ((e (select l.KEMReductionIndCca.Hon pk)))
                 (and (= ((_ is mk-some) e)
                         ((_ is mk-some) (select r.KEMReductionLazy.Hon pk)))
                      (=> ((_ is mk-some) e)
                          (= (select l.KEMIndCca.PK (maybe-get e)) (mk-some pk))))))
         (forall ((hk Int))
             (let ((p (select l.KEMIndCca.PK hk)))
                 (=> ((_ is mk-some) p)
                     (= (select l.KEMReductionIndCca.Hon (maybe-get p)) (mk-some hk)))))))

;; Handles beyond the counter are unused on both sides.
(define-state-relation handle-bound (l r)
    (forall ((h Int))
        (=> (> h l.KEMReductionIndCca.h_ctr)
            (and ((_ is mk-none) (select l.KEMReductionIndCca.Key h))
                 ((_ is mk-none) (select l.KEMReductionIndCca.Valid h))
                 ((_ is mk-none) (select r.KEMReductionLazy.Key h))
                 ((_ is mk-none) (select r.KEMReductionLazy.Alias h))
                 ((_ is mk-none) (select r.KeyLazy.Reg h))
                 ((_ is mk-none) (select r.KeyLazy.Key h))))))

(define-state-relation hc-domain (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (= ((_ is mk-some) (select l.KEMReductionIndCca.HC (mk-tuple2 pk c)))
           ((_ is mk-some) (select r.KEMReductionLazy.HC (mk-tuple2 pk c))))))

;; An honest encapsulation: its handle is registered in KeyLazy and holds the
;; same key as the T entry of the left game.
(define-state-relation hc-values (l r)
    (forall ((pk Bits_lpk) (c Bits_lct))
        (let ((e (select r.KEMReductionLazy.HC (mk-tuple2 pk c))))
            (=> ((_ is mk-some) e)
                (let ((h (maybe-get e))
                      (hk (select l.KEMReductionIndCca.Hon pk)))
                    (and (<= h r.KEMReductionLazy.h_ctr)
                         ((_ is mk-some) (select r.KeyLazy.Reg h))
                         ((_ is mk-none) (select r.KEMReductionLazy.Key h))
                         ((_ is mk-none) (select r.KEMReductionLazy.Alias h))
                         ((_ is mk-some) (select r.KeyLazy.Key h))
                         ((_ is mk-some) hk)
                         (= (select l.KEMIndCca.T (mk-tuple2 (maybe-get hk) c))
                            (select r.KeyLazy.Key h))))))))

;; A T entry always comes from an honest encapsulation.
(define-state-relation t-from-hc (l r)
    (forall ((hk Int) (c Bits_lct))
        (=> ((_ is mk-some) (select l.KEMIndCca.T (mk-tuple2 hk c)))
            (let ((p (select l.KEMIndCca.PK hk)))
                (and ((_ is mk-some) p)
                     ((_ is mk-some) (select r.KEMReductionLazy.HC (mk-tuple2 (maybe-get p) c))))))))

;; Shared keys, handle by handle.
(define-state-relation key-rel (l r)
    (forall ((h Int))
        (=> ((_ is mk-some) (select l.KEMReductionIndCca.Valid h))
            (let ((kl (select l.KEMReductionIndCca.Key h))
                  (a (select r.KEMReductionLazy.Alias h))
                  (kr (select r.KEMReductionLazy.Key h)))
                (and ((_ is mk-some) kl)
                     (ite ((_ is mk-some) a)
                          (and ((_ is mk-none) (select r.KEMReductionLazy.Key (maybe-get a)))
                               ((_ is mk-some) (select r.KeyLazy.Reg (maybe-get a)))
                               (= (select r.KeyLazy.Key (maybe-get a)) kl))
                          (ite ((_ is mk-some) kr)
                               (= kr kl)
                               (and ((_ is mk-some) (select r.KeyLazy.Reg h))
                                    (= (select r.KeyLazy.Key h) kl)))))))))

(define-state-relation invariant (l r)
    (and (upper-packages-equal l r)
         (kem-tables-equal l r)
         (keypair-shape l r)
         (hon-agree l r)
         (handle-bound l r)
         (hc-domain l r)
         (hc-values l r)
         (t-from-hc l r)
         (key-rel l r)))
