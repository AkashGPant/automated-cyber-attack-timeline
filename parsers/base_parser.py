from abc import ABC, abstractmethod
from typing import List
from models.event_model import NormalizedEvent

class BaseParser(ABC):
    @abstractmethod
    def parse(self, file_path: str) -> List[NormalizedEvent]:
        pass
