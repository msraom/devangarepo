package com.devangam.repository;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.devangam.entity.Patients;

public interface PatientHelpingHandRepository extends JpaRepository<Patients, Serializable>{

}
