"""Apply the PR #28131 bound to the installed gguf package."""
import gguf.gguf_reader as m, pathlib
p = pathlib.Path(m.__file__)
s = p.read_text()
anchor = """            offs += int(alen.nbytes)
"""
patch = anchor + """            if int(alen[0]) > 0:
                itype = GGUFValueType(int(raw_itype[0]))
                nptype = self.gguf_scalar_to_np.get(itype)
                if nptype is not None:
                    min_elem = int(np.dtype(nptype).itemsize)
                elif itype == GGUFValueType.STRING:
                    min_elem = 8
                elif itype == GGUFValueType.ARRAY:
                    min_elem = 12
                else:
                    min_elem = 1
                required = int(alen[0]) * min_elem
                if required > max(self.data.nbytes - offs, 0):
                    raise ValueError(
                        f'Array of {int(alen[0])} {itype.name} elements requires at least '
                        f'{required} bytes but only {self.data.nbytes - offs} remain')
"""
assert s.count(anchor) == 1, f"anchor found {s.count(anchor)} times"
p.write_text(s.replace(anchor, patch, 1))
print("patched", p)
