package com.example.certif.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@NoArgsConstructor

public class StudyPostDto {
    private Long id;
    private String title;
    private String content;
    private Long userId;
    private Long categoryId;
}
