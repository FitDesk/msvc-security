package com.security.services;

import com.security.dtos.trainer.TrainerRegistrationRequest;
import com.security.dtos.trainer.TrainerRegistrationResponse;

public interface TrainerService {
    TrainerRegistrationResponse registerTrainer(TrainerRegistrationRequest request);
}
