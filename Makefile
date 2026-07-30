TARGET    := atropos
BUILD_DIR := build

.PHONY: build build-windows run clean test

build:
	go build -o $(BUILD_DIR)/$(TARGET) ./cmd/$(TARGET)

build-windows:
	set GOOS=windows&&set GOARCH=amd64&&go build -o $(BUILD_DIR)/$(TARGET).exe ./cmd/$(TARGET)

run: build
	$(BUILD_DIR)/$(TARGET)

test:
	go test ./...

clean:
	rm -rf $(BUILD_DIR)
