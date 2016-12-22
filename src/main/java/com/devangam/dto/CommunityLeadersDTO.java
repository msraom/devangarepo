package com.devangam.dto;

import javax.persistence.Column;

import lombok.Data;

@Data
public class CommunityLeadersDTO {
	private long id;
	private String name;
	private String imagePath;
	private String currentDesignation;
	private String description;
}
