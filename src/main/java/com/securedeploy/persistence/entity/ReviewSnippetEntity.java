package com.securedeploy.persistence.entity;

import com.securedeploy.ai.context.SnippetType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "review_snippets")
public class ReviewSnippetEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "review_id", nullable = false)
    private ReviewEntity review;

    @Enumerated(EnumType.STRING)
    @JdbcTypeCode(SqlTypes.VARCHAR)
    @Column(nullable = false, length = 40, columnDefinition = "varchar(40)")
    private SnippetType type;

    @Column(nullable = false, length = 1000)
    private String filePath;

    @Lob
    @Column(nullable = false)
    private String content;

    protected ReviewSnippetEntity() {
    }

    public ReviewSnippetEntity(SnippetType type, String filePath, String content) {
        this.type = type;
        this.filePath = filePath;
        this.content = content;
    }

    void assignReview(ReviewEntity review) {
        this.review = review;
    }

    public SnippetType getType() {
        return type;
    }

    public String getFilePath() {
        return filePath;
    }

    public String getContent() {
        return content;
    }
}
