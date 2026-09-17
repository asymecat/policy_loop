"""PLI exporter — serialize a ``PolicyIndex`` for on-device (C++) lookup.

The device-side ``denial_check`` tool loads the PLI file this package produces
and answers the same policy queries the host-side Python engine does, so that a
verdict reached on DAYU200 is byte-identical to the one reached on the host.
"""

from .cli import main
from .pli import PLI_VERSION, compute_meta, export_file, export_text

__all__ = ["PLI_VERSION", "compute_meta", "export_file", "export_text", "main"]
