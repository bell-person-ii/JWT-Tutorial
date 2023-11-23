package me.bellperson.tutorial.repositrory;

import me.bellperson.tutorial.domain.Authority;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuthorityRepository extends JpaRepository<Authority, String> {
}
