from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any
from env.models import EngineState, Action

class TaskHandler(ABC):
    @abstractmethod
    def execute(self, state: EngineState, action: Action) -> Tuple[float, Dict[str, Any]]:
        """
        Executes the action on the state. 
        Returns (terminal_reward, info_dict).
        Terminal reward should be > 0.0 only if state.done is True and task is successful.
        """
        pass
