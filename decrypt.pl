# made by recanman
use strict;
use warnings;
use Getopt::Long;

sub xor_decrypt {
	my ($input_file, $key) = @_;

	open my $fh, '<:raw', $input_file or die "Cannot open file: $input_file\n";
	my $encrypted_data = do { local $/; <$fh> };
	close $fh;

	my $key_len = length($key);
	my $decrypted_data = '';

	for (my $i = 0; $i < length($encrypted_data); $i++) {
		my $byte = ord(substr($encrypted_data, $i, 1));
		my $decrypted_byte = $byte ^ ord(substr($key, $i % $key_len, 1));
		$decrypted_data .= chr($decrypted_byte);
	}
	return $decrypted_data;
}

sub main {
	my $input_file;
	GetOptions('file=s' => \$input_file) or die "Usage: $0 --file <encrypted_file>\n";

	if (!$input_file) {
		die "Usage: $0 --file <encrypted_file>\n";
	}

	my $key = pack('H*', '62122b0f3a1a5dd0f5ac261fdf24b99a');    
	my $decrypted_data = xor_decrypt($input_file, $key);

	print $decrypted_data;
}

main();
