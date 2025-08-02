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

public class StudyPostUpdateDto {
    private String title;
    private String content;
}
