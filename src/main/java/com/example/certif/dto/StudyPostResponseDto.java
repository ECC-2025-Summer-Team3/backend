package com.example.certif.dto;

import com.example.certif.entity.StudyPost;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor

public class StudyPostResponseDto {
    private Long postId;
    private String title;
    private String content;
    private String category;
    private LocalDateTime createdAt;
    private Long user_id;

    public static StudyPostResponseDto createStudyPostDto(StudyPost studyPost) {
        return StudyPostResponseDto.builder()
                .postId(studyPost.getId())
                .title(studyPost.getTitle())
                .content(studyPost.getContent())
                .category(studyPost.getCategory().getName())
                .createdAt(studyPost.getCreatedAt())
                .user_id(studyPost.getUser().getId())
                .build();
    }

}

