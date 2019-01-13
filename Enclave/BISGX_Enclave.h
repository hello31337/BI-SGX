#include <vector>
#include <stack>

class BISGX_stack
{
private:
	std::stack<double> st;

public:
	void push(double n) { st.push(n); }
	int size() { return (int)st.size(); }
	bool empty() { return st.empty(); }
	double pop()
	{
		if(st.empty())
		{
			const char* message = "stack underflow.";
			OCALL_print(message);
		}

		double d = st.top();
		st.pop();

		return d;
	}
};

class BISGX_memory
{
private:
	std::vector<double> mem;

public:
	void auto_resize(int n)
	{
		if(n >= (int)mem.size())
		{
			n = (n/256 + 1) * 256;
			mem.resize(n);
		}
	}
	void set(int adrs, double dt) { mem[adrs] = dt; }
	void add(int adrs, double dt) { mem[adrs] += dt; }
	double get(int adrs) {return mem[adrs]; }
	int size() { return (int)mem.size(); }
	void resize(unsigned int n) { mem.resize(n); }
};

