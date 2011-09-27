for j in `seq 1 50 1000`
do
	#Variando o batch size
	for z in 0 1
	do
		echo Running for $i $j $z
		./sendmmsg -r lo 100 $j $z
	done
done
