PROJECT_NAME = HTTPServerTester
all:
	-@mkdir __build__
	-@find src -name "*.java" > __srcs__.txt
	-@javac -source 1.7 -target 1.7 -d __build__ @__srcs__.txt
	-@jar cfe $(PROJECT_NAME).jar $(PROJECT_NAME) -C __build__ . -C src resources
	-@rm __srcs__.txt
	-@rm -r __build__