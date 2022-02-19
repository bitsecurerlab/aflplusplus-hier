#! /bin/sh

. ./tests.sh

if [ -z "$CC" ]; then
    CC=gcc
fi

export QUIET_TEST=1

export VALGRIND=
VGCODE=126

tot_tests=0
tot_pass=0
tot_fail=0
tot_config=0
tot_vg=0
tot_strange=0

base_run_test() {
    tot_tests=$((tot_tests + 1))
    if VALGRIND="$VALGRIND" "$@"; then
	tot_pass=$((tot_pass + 1))
    else
	ret="$?"
	if [ "$ret" -eq 1 ]; then
	    tot_config=$((tot_config + 1))
	elif [ "$ret" -eq 2 ]; then
	    tot_fail=$((tot_fail + 1))
	elif [ "$ret" -eq $VGCODE ]; then
	    tot_vg=$((tot_vg + 1))
	else
	    tot_strange=$((tot_strange + 1))
	fi
    fi
}

run_test () {
    echo -n "$@:	"
    if [ -n "$VALGRIND" -a -f $1.supp ]; then
	VGSUPP="--suppressions=$1.supp"
    fi
    base_run_test $VALGRIND $VGSUPP "./$@"
}

run_sh_test () {
    echo -n "$@:	"
    base_run_test sh "$@"
}

wrap_test () {
    (
	if verbose_run "$@"; then
	    PASS
	else
	    ret="$?"
	    if [ "$ret" -gt 127 ]; then
		signame=$(kill -l $((ret - 128)))
		FAIL "Killed by SIG$signame"
	    else
		FAIL "Returned error code $ret"
	    fi
	fi
    )
}

run_wrap_test () {
    echo -n "$@:	"
    base_run_test wrap_test "$@"
}

run_dtc_test () {
    echo -n "dtc $@:	"
    base_run_test wrap_test $VALGRIND $DTC "$@"
}

asm_to_so () {
    $CC -shared -o $1.test.so data.S $1.test.s
}

asm_to_so_test () {
    run_wrap_test asm_to_so "$@"
}

tree1_tests () {
    TREE=$1

    # Read-only tests
    run_test get_mem_rsv $TREE
    run_test root_node $TREE
    run_test find_property $TREE
    run_test subnode_offset $TREE
    run_test path_offset $TREE
    run_test get_name $TREE
    run_test getprop $TREE
    run_test get_phandle $TREE
    run_test get_path $TREE
    run_test supernode_atdepth_offset $TREE
    run_test parent_offset $TREE
    run_test node_offset_by_prop_value $TREE
    run_test node_offset_by_phandle $TREE
    run_test node_check_compatible $TREE
    run_test node_offset_by_compatible $TREE
    run_test notfound $TREE

    # Write-in-place tests
    run_test setprop_inplace $TREE
    run_test nop_property $TREE
    run_test nop_node $TREE
}

tree1_tests_rw () {
    TREE=$1

    # Read-write tests
    run_test set_name $TREE
    run_test setprop $TREE
    run_test del_property $TREE
    run_test del_node $TREE
}

check_tests () {
    tree="$1"
    shift
    run_sh_test dtc-checkfails.sh "$@" -- -I dts -O dtb $tree
    run_dtc_test -I dts -O dtb -o $tree.test.dtb -f $tree
    run_sh_test dtc-checkfails.sh "$@" -- -I dtb -O dtb $tree.test.dtb
}

ALL_LAYOUTS="mts mst tms tsm smt stm"

libfdt_tests () {
    tree1_tests test_tree1.dtb

    # Sequential write tests
    run_test sw_tree1
    tree1_tests sw_tree1.test.dtb
    tree1_tests unfinished_tree1.test.dtb
    run_test dtbs_equal_ordered test_tree1.dtb sw_tree1.test.dtb

    # fdt_move tests
    for tree in test_tree1.dtb sw_tree1.test.dtb unfinished_tree1.test.dtb; do
	rm -f moved.$tree shunted.$tree deshunted.$tree
	run_test move_and_save $tree
	run_test dtbs_equal_ordered $tree moved.$tree
	run_test dtbs_equal_ordered $tree shunted.$tree
	run_test dtbs_equal_ordered $tree deshunted.$tree
    done

    # v16 and alternate layout tests
    for tree in test_tree1.dtb; do
	for version in 17 16; do
	    for layout in $ALL_LAYOUTS; do
		run_test mangle-layout $tree $version $layout
		tree1_tests v$version.$layout.$tree
		run_test dtbs_equal_ordered $tree v$version.$layout.$tree
	    done
	done
    done

    # Read-write tests
    for basetree in test_tree1.dtb; do
	for version in 17 16; do
	    for layout in $ALL_LAYOUTS; do
		tree=v$version.$layout.$basetree
		rm -f opened.$tree repacked.$tree
		run_test open_pack $tree
		tree1_tests opened.$tree
		tree1_tests repacked.$tree

		tree1_tests_rw $tree
		tree1_tests_rw opened.$tree
		tree1_tests_rw repacked.$tree
	    done
	done
    done
    run_test rw_tree1
    tree1_tests rw_tree1.test.dtb
    tree1_tests_rw rw_tree1.test.dtb

    for basetree in test_tree1.dtb sw_tree1.test.dtb rw_tree1.test.dtb; do
	run_test nopulate $basetree
	run_test dtbs_equal_ordered $basetree noppy.$basetree
	tree1_tests noppy.$basetree
	tree1_tests_rw noppy.$basetree
    done

    # Tests for behaviour on various sorts of corrupted trees
    run_test truncated_property

    # Specific bug tests
    run_test add_subnode_with_nops
}

dtc_tests () {
    run_dtc_test -I dts -O dtb -o dtc_tree1.test.dtb test_tree1.dts
    tree1_tests dtc_tree1.test.dtb
    tree1_tests_rw dtc_tree1.test.dtb
    run_test dtbs_equal_ordered dtc_tree1.test.dtb test_tree1.dtb

    run_dtc_test -I dts -O dtb -o dtc_tree1_dts0.test.dtb test_tree1_dts0.dts
    tree1_tests dtc_tree1_dts0.test.dtb
    tree1_tests_rw dtc_tree1_dts0.test.dtb

    run_dtc_test -I dts -O dtb -o dtc_escapes.test.dtb escapes.dts
    run_test string_escapes dtc_escapes.test.dtb

    run_dtc_test -I dts -O dtb -o dtc_extra-terminating-null.test.dtb extra-terminating-null.dts
    run_test extra-terminating-null dtc_extra-terminating-null.test.dtb

    run_dtc_test -I dts -O dtb -o dtc_references.test.dtb references.dts
    run_test references dtc_references.test.dtb

    run_dtc_test -I dts -O dtb -o dtc_path-references.test.dtb path-references.dts
    run_test path-references dtc_path-references.test.dtb

    run_test phandle_format dtc_references.test.dtb both
    for f in legacy epapr both; do
	run_dtc_test -I dts -O dtb -H $f -o dtc_references.test.$f.dtb references.dts
	run_test phandle_format dtc_references.test.$f.dtb $f
    done

    run_dtc_test -I dts -O dtb -o multilabel.test.dtb multilabel.dts
    run_test references multilabel.test.dtb

    run_dtc_test -I dts -O dtb -o dtc_comments.test.dtb comments.dts
    run_dtc_test -I dts -O dtb -o dtc_comments-cmp.test.dtb comments-cmp.dts
    run_test dtbs_equal_ordered dtc_comments.test.dtb dtc_comments-cmp.test.dtb

    # Check aliases support in fdt_path_offset
    run_dtc_test -I dts -O dtb -o aliases.dtb aliases.dts
    run_test get_alias aliases.dtb
    run_test path_offset_aliases aliases.dtb

    # Check /include/ directive
    run_dtc_test -I dts -O dtb -o includes.test.dtb include0.dts
    run_test dtbs_equal_ordered includes.test.dtb test_tree1.dtb

    # Check /incbin/ directive
    run_dtc_test -I dts -O dtb -o incbin.test.dtb incbin.dts
    run_test incbin incbin.test.dtb

    # Check boot_cpuid_phys handling
    run_dtc_test -I dts -O dtb -o boot_cpuid.test.dtb boot-cpuid.dts
    run_test boot-cpuid boot_cpuid.test.dtb 16

    run_dtc_test -I dts -O dtb -b 17 -o boot_cpuid_17.test.dtb boot-cpuid.dts
    run_test boot-cpuid boot_cpuid_17.test.dtb 17

    run_dtc_test -I dtb -O dtb -o preserve_boot_cpuid.test.dtb boot_cpuid.test.dtb
    run_test boot-cpuid preserve_boot_cpuid.test.dtb 16
    run_test dtbs_equal_ordered preserve_boot_cpuid.test.dtb boot_cpuid.test.dtb

    run_dtc_test -I dtb -O dtb -o preserve_boot_cpuid_17.test.dtb boot_cpuid_17.test.dtb
    run_test boot-cpuid preserve_boot_cpuid_17.test.dtb 17
    run_test dtbs_equal_ordered preserve_boot_cpuid_17.test.dtb boot_cpuid_17.test.dtb

    run_dtc_test -I dtb -O dtb -b17 -o override17_boot_cpuid.test.dtb boot_cpuid.test.dtb
    run_test boot-cpuid override17_boot_cpuid.test.dtb 17

    run_dtc_test -I dtb -O dtb -b0 -o override0_boot_cpuid_17.test.dtb boot_cpuid_17.test.dtb
    run_test boot-cpuid override0_boot_cpuid_17.test.dtb 0


    # Check -Oasm mode
    for tree in test_tree1.dts escapes.dts references.dts path-references.dts \
	comments.dts aliases.dts include0.dts incbin.dts \
	value-labels.dts ; do
	run_dtc_test -I dts -O asm -o oasm_$tree.test.s $tree
	asm_to_so_test oasm_$tree
	run_dtc_test -I dts -O dtb -o $tree.test.dtb $tree
	run_test asm_tree_dump ./oasm_$tree.test.so oasm_$tree.test.dtb
	run_wrap_test cmp oasm_$tree.test.dtb $tree.test.dtb
    done

    run_test value-labels ./oasm_value-labels.dts.test.so

    # Check -Odts mode preserve all dtb information
    for tree in test_tree1.dtb dtc_tree1.test.dtb dtc_escapes.test.dtb \
	dtc_extra-terminating-null.test.dtb dtc_references.test.dtb; do
	run_dtc_test -I dtb -O dts -o odts_$tree.test.dts $tree
	run_dtc_test -I dts -O dtb -o odts_$tree.test.dtb odts_$tree.test.dts
	run_test dtbs_equal_ordered $tree odts_$tree.test.dtb
    done

    # Check version conversions
    for tree in test_tree1.dtb ; do
	 for aver in 1 2 3 16 17; do
	     atree="ov${aver}_$tree.test.dtb"
	     run_dtc_test -I dtb -O dtb -V$aver -o $atree $tree
	     for bver in 16 17; do
		 btree="ov${bver}_$atree"
		 run_dtc_test -I dtb -O dtb -V$bver -o $btree $atree
		 run_test dtbs_equal_ordered $btree $tree
	     done
	 done
    done

    # Check merge/overlay functionality
    run_dtc_test -I dts -O dtb -o dtc_tree1_merge.test.dtb test_tree1_merge.dts
    tree1_tests dtc_tree1_merge.test.dtb test_tree1.dtb
    run_dtc_test -I dts -O dtb -o dtc_tree1_merge_labelled.test.dtb test_tree1_merge_labelled.dts
    tree1_tests dtc_tree1_merge_labelled.test.dtb test_tree1.dtb
    run_dtc_test -I dts -O dtb -o multilabel_merge.test.dtb multilabel_merge.dts
    run_test references multilabel.test.dtb
    run_test dtbs_equal_ordered multilabel.test.dtb multilabel_merge.test.dtb
    run_dtc_test -I dts -O dtb -o dtc_tree1_merge_path.test.dtb test_tree1_merge_path.dts
    tree1_tests dtc_tree1_merge_path.test.dtb test_tree1.dtb

    # Check some checks
    check_tests dup-nodename.dts duplicate_node_names
    check_tests dup-propname.dts duplicate_property_names
    check_tests dup-phandle.dts explicit_phandles
    check_tests zero-phandle.dts explicit_phandles
    check_tests minusone-phandle.dts explicit_phandles
    run_sh_test dtc-checkfails.sh phandle_references -- -I dts -O dtb nonexist-node-ref.dts
    run_sh_test dtc-checkfails.sh phandle_references -- -I dts -O dtb nonexist-label-ref.dts
    run_sh_test dtc-fatal.sh -I dts -O dtb nonexist-node-ref2.dts
    check_tests bad-name-property.dts name_properties

    check_tests bad-ncells.dts address_cells_is_cell size_cells_is_cell interrupt_cells_is_cell
    check_tests bad-string-props.dts device_type_is_string model_is_string status_is_string
    check_tests bad-reg-ranges.dts reg_format ranges_format
    check_tests bad-empty-ranges.dts ranges_format
    check_tests reg-ranges-root.dts reg_format ranges_format
    check_tests default-addr-size.dts avoid_default_addr_size
    check_tests obsolete-chosen-interrupt-controller.dts obsolete_chosen_interrupt_controller
    run_sh_test dtc-checkfails.sh node_name_chars -- -I dtb -O dtb bad_node_char.dtb
    run_sh_test dtc-checkfails.sh node_name_format -- -I dtb -O dtb bad_node_format.dtb
    run_sh_test dtc-checkfails.sh prop_name_chars -- -I dtb -O dtb bad_prop_char.dtb

    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label1.dts
    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label2.dts
    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label3.dts
    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label4.dts
    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label5.dts
    run_sh_test dtc-checkfails.sh duplicate_label -- -I dts -O dtb reuse-label6.dts

    # Check for proper behaviour reading from stdin
    run_dtc_test -I dts -O dtb -o stdin_dtc_tree1.test.dtb - < test_tree1.dts
    run_wrap_test cmp stdin_dtc_tree1.test.dtb dtc_tree1.test.dtb
    run_dtc_test -I dtb -O dts -o stdin_odts_test_tree1.dtb.test.dts - < test_tree1.dtb
    run_wrap_test cmp stdin_odts_test_tree1.dtb.test.dts odts_test_tree1.dtb.test.dts

    # Check for graceful failure in some error conditions
    run_sh_test dtc-fatal.sh -I dts -O dtb nosuchfile.dts
    run_sh_test dtc-fatal.sh -I dtb -O dtb nosuchfile.dtb
    run_sh_test dtc-fatal.sh -I fs -O dtb nosuchfile
}

cmp_tests () {
    basetree="$1"
    shift
    wrongtrees="$@"

    run_test dtb_reverse $basetree

    # First dtbs_equal_ordered
    run_test dtbs_equal_ordered $basetree $basetree
    run_test dtbs_equal_ordered -n $basetree $basetree.reversed.test.dtb
    for tree in $wrongtrees; do
	run_test dtbs_equal_ordered -n $basetree $tree
    done

    # now unordered
    run_test dtbs_equal_unordered $basetree $basetree
    run_test dtbs_equal_unordered $basetree $basetree.reversed.test.dtb
    run_test dtbs_equal_unordered $basetree.reversed.test.dtb $basetree
    for tree in $wrongtrees; do
	run_test dtbs_equal_unordered -n $basetree $tree
    done

    # now dtc --sort
    run_dtc_test -I dtb -O dtb -s -o $basetree.sorted.test.dtb $basetree
    run_test dtbs_equal_unordered $basetree $basetree.sorted.test.dtb
    run_dtc_test -I dtb -O dtb -s -o $basetree.reversed.sorted.test.dtb $basetree.reversed.test.dtb
    run_test dtbs_equal_unordered $basetree.reversed.test.dtb $basetree.reversed.sorted.test.dtb
    run_test dtbs_equal_ordered $basetree.sorted.test.dtb $basetree.reversed.sorted.test.dtb
}

dtbs_equal_tests () {
    WRONG_TREE1=""
    for x in 1 2 3 4 5 6 7 8 9; do
	run_dtc_test -I dts -O dtb -o test_tree1_wrong$x.test.dtb test_tree1_wrong$x.dts
	WRONG_TREE1="$WRONG_TREE1 test_tree1_wrong$x.test.dtb"
    done
    cmp_tests test_tree1.dtb $WRONG_TREE1
}

while getopts "vt:m" ARG ; do
    case $ARG in
	"v")
	    unset QUIET_TEST
	    ;;
	"t")
	    TESTSETS=$OPTARG
	    ;;
	"m")
	    VALGRIND="valgrind --tool=memcheck -q --error-exitcode=$VGCODE"
	    ;;
    esac
done

if [ -z "$TESTSETS" ]; then
    TESTSETS="libfdt dtc dtbs_equal"
fi

# Make sure we don't have stale blobs lying around
rm -f *.test.dtb *.test.dts

for set in $TESTSETS; do
    case $set in
	"libfdt")
	    libfdt_tests
	    ;;
	"dtc")
	    dtc_tests
	    ;;
	"dtbs_equal")
	    dtbs_equal_tests
	    ;;
    esac
done

echo "********** TEST SUMMARY"
echo "*     Total testcases:	$tot_tests"
echo "*                PASS:	$tot_pass"
echo "*                FAIL:	$tot_fail"
echo "*   Bad configuration:	$tot_config"
if [ -n "$VALGRIND" ]; then
    echo "*    valgrind errors:	$tot_vg"
fi
echo "* Strange test result:	$tot_strange"
echo "**********"

