package com.example.certif.entity;

import com.example.certif.dto.StudyPostDto;
import com.example.certif.dto.StudyPostUpdateDto;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "study_post")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class StudyPost {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 200, nullable = false)
    private String title;

    @Lob
    @Column(nullable = false)
    private String content;

    @Column(name = "created_at", nullable = false, updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @UpdateTimestamp
    private LocalDateTime updatedAt;

    // 사용자 외래키
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    private User user;

    // 카테고리 외래키
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "category_id")
    private Category category;

    public static StudyPost createStudyPost(StudyPostDto dto, User user, Category category) {
        return StudyPost.builder()
                .title(dto.getTitle())
                .content(dto.getContent())
                .user(user)
                .category(category)
                .build();
    }

    public void patch(StudyPostUpdateDto dto) {
        if (dto.getTitle() != null && !dto.getTitle().isEmpty()) {
            this.title = dto.getTitle();
        }
        if (dto.getContent() != null && !dto.getContent().isEmpty()) {
            this.content = dto.getContent();
        }
    }
}
