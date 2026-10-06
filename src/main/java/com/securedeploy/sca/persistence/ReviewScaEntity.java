package com.securedeploy.sca.persistence;

import com.securedeploy.persistence.entity.ReviewEntity;
import com.securedeploy.sca.model.ScaResult;
import jakarta.persistence.*;

@Entity
@Table(name = "review_sca_reports")
public class ReviewScaEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "review_id", nullable = false, unique = true)
    private ReviewEntity review;

    @Convert(converter = ScaResultConverter.class)
    @Column(name = "result_json", nullable = false, columnDefinition = "TEXT")
    private ScaResult result;

    protected ReviewScaEntity() { }
    public ReviewScaEntity(ReviewEntity review, ScaResult result) {
        this.review = review;
        this.result = result;
    }
    public ScaResult getResult() { return result; }
}
