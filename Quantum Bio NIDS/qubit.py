import random

class qubit:

	def __init__(self, count):
	
		"""
		Qubit Class that represents the property 
		of superposition between 0 and 1.
		
		@input: count
		takes an integer type as the number of qubits to instantiate.
		"""
		self._counts
		self._qubits = qubits
	
	@property
	def qubits(self):
		return self._qubits
	
	@qubits.setter
	def observe(self):
		"""
		Observe qubits to determine values
		
		"""
		self._qubits = [None for i in range(count)]:
		for i in range(self._count):
			r = random.uniform(0,1)
			if r <= 5.0:
				self._qubits[i] = 0
			else:
				self._qubits[i] = 1