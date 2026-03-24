"""
KitNET Adapter for Mateen Framework

This adapter makes KitNET compatible with Mateen's PyTorch autoencoder interface,
allowing KitNET to be used as a drop-in replacement for the PyTorch models.
"""

import numpy as np
import sys
import os

# Add path to KitNET (go up two levels from MateenUtils to root, then to KitNET)
current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(os.path.dirname(current_dir))
sys.path.insert(0, root_dir)

from KitNET.KitNET import KitNET


class KitNETAdapter:
    """
    Adapter to make KitNET compatible with Mateen's PyTorch autoencoder interface.
    
    This class wraps KitNET and provides methods that match the PyTorch autoencoder
    interface, allowing KitNET to be used as a drop-in replacement in Mateen.
    """
    
    def __init__(self, feature_size):
        """
        Initialize KitNET adapter.
        
        Args:
            feature_size: Number of input features (n)
        """
        self.feature_size = feature_size
        # Reduced grace periods for faster training (we have plenty of data)
        # FM_grace_period: samples needed to learn feature mapping
        # AD_grace_period: samples needed to train autoencoders
        # Default KitNET uses 10,000 for AD, but we can use less with large datasets
        self.kitnet = KitNET(
            n=feature_size,
            max_autoencoder_size=10,
            FM_grace_period=5000,   # 5K samples for feature mapping (sufficient)
            AD_grace_period=10000,  # 10K samples for autoencoder training (default, sufficient)
            learning_rate=0.1,
            hidden_ratio=0.75
        )
        self.trained = False
        self.training_samples = []
        self._is_eval_mode = False
        
    def forward(self, x):
        """
        Mimic PyTorch forward pass - returns reconstruction.
        
        Note: KitNET doesn't return reconstruction, so we return the input.
        This is only used for compatibility. Actual error is from process().
        
        Args:
            x: Input tensor (numpy array or torch tensor)
        
        Returns:
            Input (as reconstruction for compatibility)
        """
        # KitNET doesn't return reconstruction, so we return input
        # This is only used for compatibility, actual error is from process()
        if isinstance(x, np.ndarray):
            return x
        return x.numpy() if hasattr(x, 'numpy') else x
    
    def __call__(self, x):
        """
        Make the adapter callable like PyTorch models.
        
        Args:
            x: Input tensor (torch.Tensor or numpy array), can be single sample or batch
        
        Returns:
            Reconstruction (for compatibility, returns input as torch tensor)
        """
        import torch
        # Convert torch tensor to numpy if needed
        if isinstance(x, torch.Tensor):
            x_np = x.cpu().numpy()
            is_torch = True
        else:
            x_np = np.array(x)
            is_torch = False
        
        # Handle single sample vs batch
        if x_np.ndim == 1:
            x_np = x_np.reshape(1, -1)
            was_single = True
        else:
            was_single = False
        
        # For compatibility, return the input as "reconstruction"
        result = self.forward(x_np)
        
        # Convert back to torch tensor if input was torch
        if is_torch:
            result_tensor = torch.from_numpy(result).float()
            if was_single:
                return result_tensor.squeeze(0)
            return result_tensor
        else:
            if was_single:
                return result.squeeze(0)
            return result
    
    def eval(self):
        """Mimic PyTorch eval mode."""
        self._is_eval_mode = True
        return self
    
    def train(self, mode=True):
        """Mimic PyTorch train mode."""
        self._is_eval_mode = not mode
        return self
    
    def to(self, device):
        """Mimic PyTorch device placement (no-op for KitNET)."""
        return self
    
    def process_batch(self, x_batch, show_progress=False):
        """
        Process batch of samples and return RMSE scores.
        
        This replaces the reconstruction error calculation in Mateen.
        
        Args:
            x_batch: Batch of input samples (numpy array, shape: (batch_size, n_features))
            show_progress: If True, show progress for large batches
        
        Returns:
            RMSE scores for each sample (numpy array, shape: (batch_size,))
        """
        import time
        
        total_samples = len(x_batch)
        if total_samples == 0:
            return np.array([])
        
        # Only show progress for large batches (>10K samples)
        if show_progress and total_samples > 10000:
            print(f"Processing {total_samples:,} samples for inference...")
            start_time = time.time()
            print_interval = max(1, total_samples // 10)  # Print every 10%
        
        rmse_scores = []
        for idx, x in enumerate(x_batch):
            if isinstance(x, np.ndarray):
                rmse, _ = self.kitnet.process(x)
            else:
                # Handle torch tensors
                x_np = x.numpy() if hasattr(x, 'numpy') else np.array(x)
                rmse, _ = self.kitnet.process(x_np)
            rmse_scores.append(rmse)
            
            # Print progress for large batches
            if show_progress and total_samples > 10000:
                if (idx + 1) % print_interval == 0 or (idx + 1) == total_samples:
                    current_time = time.time()
                    elapsed = current_time - start_time
                    rate = (idx + 1) / elapsed if elapsed > 0 else 0
                    remaining = (total_samples - idx - 1) / rate if rate > 0 else 0
                    print(f"Inference Progress: {idx+1:,}/{total_samples:,} ({100*(idx+1)/total_samples:.1f}%) | "
                          f"Rate: {rate:.0f} samples/sec | "
                          f"Elapsed: {elapsed:.1f}s | "
                          f"Remaining: {remaining:.1f}s")
        
        if show_progress and total_samples > 10000:
            total_time = time.time() - start_time
            print(f"Inference completed in {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
        
        return np.array(rmse_scores)
    
    def train_on_data(self, x_train, num_epochs=100):
        """
        Train KitNET on data (online training).
        
        KitNET trains online, so we process each sample once.
        The num_epochs parameter is ignored for KitNET.
        
        Args:
            x_train: Training data (numpy array, shape: (n_samples, n_features))
            num_epochs: Ignored (KitNET trains online)
        
        Returns:
            Self (for chaining)
        """
        import time
        from datetime import datetime
        
        total_samples = len(x_train)
        grace_period = self.kitnet.FM_grace_period + self.kitnet.AD_grace_period
        
        print(f"Training KitNET on {total_samples:,} samples...")
        print(f"Grace period: {grace_period:,} samples (FM: {self.kitnet.FM_grace_period:,}, AD: {self.kitnet.AD_grace_period:,})")
        print(f"Progress will be shown every 10% of samples")
        print()
        
        start_time = time.time()
        last_print_time = start_time
        print_interval = max(1, total_samples // 10)  # Print every 10%
        
        # KitNET trains online, so we just process each sample
        for idx, x in enumerate(x_train):
            if isinstance(x, np.ndarray):
                self.kitnet.process(x)
            else:
                # Handle torch tensors
                x_np = x.numpy() if hasattr(x, 'numpy') else np.array(x)
                self.kitnet.process(x_np)
            
            # Print progress periodically
            if (idx + 1) % print_interval == 0 or (idx + 1) == total_samples:
                current_time = time.time()
                elapsed = current_time - start_time
                rate = (idx + 1) / elapsed if elapsed > 0 else 0
                remaining = (total_samples - idx - 1) / rate if rate > 0 else 0
                
                phase = "Feature Mapping" if self.kitnet.n_trained <= self.kitnet.FM_grace_period else \
                       "Autoencoder Training" if self.kitnet.n_trained <= grace_period else \
                       "Inference Mode"
                
                print(f"Progress: {idx+1:,}/{total_samples:,} ({100*(idx+1)/total_samples:.1f}%) | "
                      f"Phase: {phase} | "
                      f"Rate: {rate:.0f} samples/sec | "
                      f"Elapsed: {elapsed:.1f}s | "
                      f"Remaining: {remaining:.1f}s")
        
        total_time = time.time() - start_time
        print(f"\nTraining completed in {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
        print(f"Average rate: {total_samples/total_time:.0f} samples/sec")
        self.trained = True
        return self
    
    def fine_tune(self, x_train, num_epochs=10):
        """
        Fine-tune KitNET on new data.
        
        Uses KitNET's fine_tune method with reduced learning rate.
        
        Args:
            x_train: Fine-tuning data (numpy array, shape: (n_samples, n_features))
            num_epochs: Ignored (KitNET fine-tunes online)
        
        Returns:
            Self (for chaining)
        """
        import time
        
        total_samples = len(x_train)
        if total_samples == 0:
            return self
        
        print(f"Fine-tuning KitNET on {total_samples:,} samples...")
        start_time = time.time()
        # For small batches, show progress more frequently
        if total_samples < 100:
            print_interval = max(1, total_samples // 5)  # Print every 20% for small batches
        else:
            print_interval = max(1, total_samples // 10)  # Print every 10% for larger batches
        
        for idx, x in enumerate(x_train):
            if isinstance(x, np.ndarray):
                self.kitnet.fine_tune(x, learning_rate_multiplier=0.1)
            else:
                # Handle torch tensors
                x_np = x.numpy() if hasattr(x, 'numpy') else np.array(x)
                self.kitnet.fine_tune(x_np, learning_rate_multiplier=0.1)
            
            # Print progress periodically
            if (idx + 1) % print_interval == 0 or (idx + 1) == total_samples:
                current_time = time.time()
                elapsed = current_time - start_time
                rate = (idx + 1) / elapsed if elapsed > 0 else 0
                remaining = (total_samples - idx - 1) / rate if rate > 0 else 0
                
                print(f"Fine-tune Progress: {idx+1:,}/{total_samples:,} ({100*(idx+1)/total_samples:.1f}%) | "
                      f"Rate: {rate:.0f} samples/sec | "
                      f"Elapsed: {elapsed:.1f}s | "
                      f"Remaining: {remaining:.1f}s")
        
        total_time = time.time() - start_time
        print(f"Fine-tuning completed in {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
        return self
    
    def clone(self):
        """
        Create a clone of this model.
        
        Returns:
            Cloned KitNETAdapter instance
        """
        cloned = KitNETAdapter(self.feature_size)
        cloned.kitnet = self.kitnet.clone_from(self.kitnet)
        cloned.trained = self.trained
        cloned._is_eval_mode = self._is_eval_mode
        return cloned
    
    def __deepcopy__(self, memo):
        """Support for copy.deepcopy."""
        return self.clone()
    
    def state_dict(self):
        """
        Mimic PyTorch state_dict for compatibility with merge operations.
        
        Returns:
            Empty dict (KitNET doesn't use state_dict, but needed for merge compatibility)
        """
        # Return empty dict since KitNET doesn't use PyTorch's state_dict mechanism
        # Model merging for KitNET is handled differently (via clone and fine-tune)
        return {}

