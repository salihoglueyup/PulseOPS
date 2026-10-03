from pydantic import BaseModel, Field

class ContainerSummary(BaseModel):
    id: str
    name: str
    image: str
    status: str                       # Up 2 hours, Exited (0) 5 minutes ago, etc.
    ports: list[str] = Field(default_factory=list)
    uptime: str = ""

    @property
    def is_running(self) -> bool:
        return self.status.lower().startswith("up")

    @property
    def status_badge(self) -> str:
        if self.is_running:
            return "[bold green]ÇALIŞIYOR ✓[/bold green]"
        return "[dim red]DURDU[/dim red]"
