provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "fuzzer_sg" {
  name        = "fuzzer-sg"
  description = "Security group for AFL fuzzing instance"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "fuzzer" {
  ami           = "ami-0c02fb55956c7d316"
  instance_type = "c5.2xlarge"
  key_name      = "fuzzer-key"
  security_group_ids = [aws_security_group.fuzzer_sg.id]

  root_block_device {
    volume_size = 50
    volume_type = "gp3"
  }

  user_data = <<-EOF
              #!/bin/bash
              apt-get update
              apt-get install -y build-essential git python3 python3-pip gdb
              pip3 install pytest psutil
              git clone https://github.com/AFLplusplus/AFLplusplus.git /opt/AFLplusplus
              cd /opt/AFLplusplus && make distrib && make install
              EOF

  tags = {
    Name = "afl-fuzzer-instance"
    Project = "embedded-c-afl-fuzzer"
  }
}

resource "aws_ebs_volume" "crash_corpus" {
  availability_zone = aws_instance.fuzzer.availability_zone
  size              = 100
  type              = "gp3"
  tags = {
    Name = "crash-corpus-volume"
  }
}

resource "aws_volume_attachment" "crash_corpus_attach" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.crash_corpus.id
  instance_id = aws_instance.fuzzer.id
}

resource "aws_s3_bucket" "crash_storage" {
  bucket = "afl-fuzzer-crash-corpus"
  tags = {
    Name = "afl-crash-storage"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "crash_lifecycle" {
  bucket = aws_s3_bucket.crash_storage.id

  rule {
    id     = "archive-crashes"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}

output "fuzzer_public_ip" {
  value = aws_instance.fuzzer.public_ip
}

output "s3_bucket_name" {
  value = aws_s3_bucket.crash_storage.bucket
}